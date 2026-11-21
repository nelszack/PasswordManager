//! Encrypted file attachments. Attachments live inside the vault document, so
//! backups, sync, history-free trash, and portable exports carry them without
//! separate storage. Tight limits keep whole-vault saves and uploads fast.
use super::*;

pub const MAX_ATTACHMENT_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_VAULT_ATTACHMENT_BYTES: usize = 25 * 1024 * 1024;
pub const MAX_ATTACHMENTS_PER_ITEM: usize = 32;
pub const MAX_ATTACHMENT_NAME_BYTES: usize = 255;

#[derive(Clone, PartialEq, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub(crate) struct Attachment {
    pub name: String,
    pub added: Timestamp,
    #[serde(with = "raw_bytes")]
    pub data: Vec<u8>,
}

impl std::fmt::Debug for Attachment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attachment")
            .field("name", &self.name)
            .field("size", &self.data.len())
            .finish_non_exhaustive()
    }
}

impl Attachment {
    pub(super) fn info(&self) -> pm_contracts::vault::AttachmentInfo {
        pm_contracts::vault::AttachmentInfo {
            name: self.name.clone(),
            size: self.data.len() as u64,
            added: self.added.to_string(),
        }
    }
}

/// MessagePack `bin` encoding: a plain `Vec<u8>` would be written as an array
/// of integers, nearly doubling the size of binary content.
mod raw_bytes {
    use serde::{Deserializer, Serializer, de};

    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        struct Bytes;
        impl<'de> de::Visitor<'de> for Bytes {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("attachment bytes")
            }
            fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Vec<u8>, E> {
                Ok(value.to_vec())
            }
            fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(value)
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
                let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(1 << 20));
                while let Some(byte) = seq.next_element::<u8>()? {
                    bytes.push(byte);
                }
                Ok(bytes)
            }
        }
        deserializer.deserialize_bytes(Bytes)
    }
}

/// Trims and checks a display/file name. Separators and control characters are
/// rejected because the name becomes a file name when an attachment is saved.
pub(super) fn check_name(name: &str) -> Result<String, VaultError> {
    let name = name.trim();
    if name.is_empty() || name.len() > MAX_ATTACHMENT_NAME_BYTES {
        return Err(VaultError::InvalidInput(format!(
            "Attachment names must be 1 to {MAX_ATTACHMENT_NAME_BYTES} bytes"
        )));
    }
    if name == "."
        || name == ".."
        || name
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\'))
    {
        return Err(VaultError::InvalidInput(
            "Attachment names cannot contain path separators or control characters".into(),
        ));
    }
    Ok(name.to_owned())
}

/// Checks one item's attachments as stored (decode and import).
pub(super) fn check_stored(attachments: &[Attachment]) -> Result<(), VaultError> {
    if attachments.len() > MAX_ATTACHMENTS_PER_ITEM {
        return Err(VaultError::Validation(format!(
            "items are limited to {MAX_ATTACHMENTS_PER_ITEM} attachments"
        )));
    }
    let mut names = HashSet::new();
    for attachment in attachments {
        if check_name(&attachment.name)? != attachment.name
            || !names.insert(attachment.name.to_lowercase())
        {
            return Err(VaultError::Validation(
                "attachment names must be trimmed and unique within an item".into(),
            ));
        }
        if attachment.data.len() > MAX_ATTACHMENT_BYTES {
            return Err(VaultError::Validation(
                "an attachment exceeds the 5 MiB limit".into(),
            ));
        }
    }
    Ok(())
}

impl Item {
    pub(super) fn attachment_bytes(&self) -> usize {
        self.attachments.iter().map(|a| a.data.len()).sum()
    }
    fn attachment(&self, name: &str) -> Result<&Attachment, VaultError> {
        let name = name.trim();
        self.attachments
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(name))
            .ok_or_else(|| VaultError::NotFound(format!("no attachment is named {name:?}")))
    }
}

impl Vault {
    /// Attachment bytes held by every item, including trashed ones, which are
    /// still stored and restorable.
    pub(super) fn total_attachment_bytes(&self) -> usize {
        self.data.items.values().map(Item::attachment_bytes).sum()
    }

    pub fn add_attachment(
        &mut self,
        target: &Target,
        name: &str,
        data: Zeroizing<Vec<u8>>,
        key: &mut VaultCredentials,
    ) -> Result<(), VaultError> {
        let name = check_name(name)?;
        if data.len() > MAX_ATTACHMENT_BYTES {
            return Err(VaultError::InvalidInput(format!(
                "Attachments are limited to {} MiB each",
                MAX_ATTACHMENT_BYTES / (1024 * 1024)
            )));
        }
        let item = self.require_target(target)?;
        if item.is_passkey() {
            return Err(VaultError::InvalidInput(
                "Passkey records cannot have attachments".into(),
            ));
        }
        if item.attachments.len() >= MAX_ATTACHMENTS_PER_ITEM {
            return Err(VaultError::InvalidInput(format!(
                "Items are limited to {MAX_ATTACHMENTS_PER_ITEM} attachments"
            )));
        }
        if item.attachment(&name).is_ok() {
            return Err(VaultError::InvalidInput(format!(
                "This item already has an attachment named {name:?}; remove it or choose another \
                 name"
            )));
        }
        if self.total_attachment_bytes().saturating_add(data.len()) > MAX_VAULT_ATTACHMENT_BYTES {
            return Err(VaultError::InvalidInput(format!(
                "Attachments are limited to {} MiB per vault",
                MAX_VAULT_ATTACHMENT_BYTES / (1024 * 1024)
            )));
        }
        let id = item.entry.id;
        self.transaction(TransactionScope::Entry(id), key, |vault| {
            let item = vault.item_mut(id).expect("selected item");
            let now = Timestamp::now();
            item.attachments.push(Attachment {
                name,
                added: now.clone(),
                data: data.to_vec(),
            });
            item.entry.modified = now;
            Ok((true, ()))
        })
    }

    pub fn remove_attachment(
        &mut self,
        target: &Target,
        name: &str,
        key: &mut VaultCredentials,
    ) -> Result<(), VaultError> {
        let item = self.require_target(target)?;
        let stored = item.attachment(name)?.name.clone();
        let id = item.entry.id;
        self.transaction(TransactionScope::Entry(id), key, |vault| {
            let item = vault.item_mut(id).expect("selected item");
            item.attachments.retain(|a| a.name != stored);
            item.entry.modified = Timestamp::now();
            Ok((true, ()))
        })
    }

    pub fn attachment_data(
        &self,
        target: &Target,
        name: &str,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        Ok(Zeroizing::new(
            self.require_target(target)?.attachment(name)?.data.clone(),
        ))
    }

    /// Writes an attachment to a new private file (or replaces one with `force`).
    pub fn save_attachment(
        &self,
        target: &Target,
        name: &str,
        path: &str,
        force: bool,
    ) -> Result<(), VaultError> {
        let item = self.require_target(target)?;
        let attachment = item.attachment(name)?;
        persistence::persist_private_stream(Path::new(path), force, |file| {
            file.write_all(&attachment.data)
                .map_err(|e| VaultError::Persistence(format!("could not write attachment: {e}")))
        })
    }
}

/// Reads a file the user chose to attach, enforcing the per-file limit before
/// loading it.
pub(crate) fn read_attachment_file(path: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    crate::file::read_bounded_file(Path::new(path), MAX_ATTACHMENT_BYTES as u64).map_err(|error| {
        if error.kind() == std::io::ErrorKind::InvalidData {
            VaultError::InvalidInput(format!(
                "Attachments are limited to {} MiB each",
                MAX_ATTACHMENT_BYTES / (1024 * 1024)
            ))
        } else {
            VaultError::InvalidInput(format!("could not read {path:?}: {error}"))
        }
    })
}

/// The name an attachment gets when the user does not choose one.
pub(crate) fn default_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("attachment")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Vault, VaultCredentials, usize) {
        let mut vault = Vault::memory();
        let mut key = VaultCredentials::default();
        vault
            .add_typed_entry(
                TypedEntry {
                    entry: PasswordEntry {
                        name: "Holder".into(),
                        username: None,
                        password: "synthetic".into(),
                        url: None,
                        notes: None,
                        copy: false,
                    },
                    kind: ItemKind::SecureNote,
                    additional_urls: vec![],
                    custom_fields: vec![],
                    tags: vec![],
                    favorite: false,
                },
                &mut key,
            )
            .unwrap();
        let id = vault
            .entry_id(&Target::Name("Holder".into()))
            .unwrap()
            .unwrap();
        (vault, key, id)
    }

    fn schema(document: &[u8]) -> u16 {
        #[derive(Deserialize)]
        struct Header {
            schema_version: u16,
        }
        rmp_serde::from_slice::<Header>(document)
            .unwrap()
            .schema_version
    }

    #[test]
    fn attachments_round_trip_through_the_encrypted_document_compactly() {
        let (mut vault, mut key, id) = fixture();
        let target = Target::Id(id);
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        vault
            .add_attachment(
                &target,
                " recovery.pdf ",
                Zeroizing::new(data.clone()),
                &mut key,
            )
            .unwrap();
        assert_eq!(
            *vault.attachment_data(&target, "RECOVERY.PDF").unwrap(),
            data
        );
        let detail = vault.management_item(id, false).unwrap();
        assert_eq!(detail.attachments.len(), 1);
        assert_eq!(detail.attachments[0].name, "recovery.pdf");
        assert_eq!(detail.attachments[0].size, 4096);

        let bytes = persistence::encode_document(&vault.data, None).unwrap();
        // Binary encoding: one byte per content byte plus a small envelope.
        assert!(bytes.len() < 4096 + 1024, "{} bytes", bytes.len());
        assert_eq!(schema(&bytes), 3);
        assert_eq!(persistence::decode_document(&bytes).unwrap(), vault.data);

        vault
            .remove_attachment(&target, "recovery.PDF", &mut key)
            .unwrap();
        assert!(vault.attachment_data(&target, "recovery.pdf").is_err());
        let bytes = persistence::encode_document(&vault.data, None).unwrap();
        assert_eq!(schema(&bytes), 2);
    }

    #[test]
    fn attachment_names_sizes_counts_and_vault_totals_are_limited() {
        let (mut vault, mut key, id) = fixture();
        let target = Target::Id(id);
        let small = || Zeroizing::new(vec![1u8; 16]);
        for bad in ["", "  ", "a/b", "a\\b", "..", "x\u{0}y"] {
            assert!(
                vault
                    .add_attachment(&target, bad, small(), &mut key)
                    .is_err(),
                "{bad:?}"
            );
        }
        let long = "n".repeat(MAX_ATTACHMENT_NAME_BYTES + 1);
        assert!(
            vault
                .add_attachment(&target, &long, small(), &mut key)
                .is_err()
        );
        assert!(
            vault
                .add_attachment(
                    &target,
                    "big",
                    Zeroizing::new(vec![0; MAX_ATTACHMENT_BYTES + 1]),
                    &mut key
                )
                .is_err()
        );
        vault
            .add_attachment(&target, "one", small(), &mut key)
            .unwrap();
        assert!(
            vault
                .add_attachment(&target, "ONE", small(), &mut key)
                .is_err()
        );
        for i in 1..MAX_ATTACHMENTS_PER_ITEM {
            vault
                .add_attachment(&target, &format!("f{i}"), small(), &mut key)
                .unwrap();
        }
        assert!(
            vault
                .add_attachment(&target, "extra", small(), &mut key)
                .is_err()
        );

        // The vault-wide budget counts every item, including trashed ones.
        let (mut vault, mut key, id) = fixture();
        let target = Target::Id(id);
        for i in 0..(MAX_VAULT_ATTACHMENT_BYTES / MAX_ATTACHMENT_BYTES) {
            vault
                .add_attachment(
                    &target,
                    &format!("chunk{i}"),
                    Zeroizing::new(vec![0; MAX_ATTACHMENT_BYTES]),
                    &mut key,
                )
                .unwrap();
        }
        vault.delete_entry(target.clone(), &mut key).unwrap();
        assert_eq!(vault.total_attachment_bytes(), MAX_VAULT_ATTACHMENT_BYTES);
    }

    #[test]
    fn saved_attachments_are_private_and_do_not_overwrite_without_force() {
        let (mut vault, mut key, id) = fixture();
        let target = Target::Id(id);
        vault
            .add_attachment(
                &target,
                "notes.txt",
                Zeroizing::new(b"hello".to_vec()),
                &mut key,
            )
            .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("out.txt");
        let path = path.to_str().unwrap();
        vault
            .save_attachment(&target, "notes.txt", path, false)
            .unwrap();
        assert_eq!(fs::read(path).unwrap(), b"hello");
        assert!(
            vault
                .save_attachment(&target, "notes.txt", path, false)
                .is_err()
        );
        vault
            .save_attachment(&target, "notes.txt", path, true)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
