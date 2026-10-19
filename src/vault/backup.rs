use super::*;
const BACKUP_DOCUMENT_VERSION: u8 = 2;
impl Vault {
    pub fn encrypted_backup(
        &self,
        path: String,
        key: &mut PasswordType,
        force: bool,
    ) -> Result<(), VaultError> {
        self.encrypted_backup_with_limit(path, key, force, MAX_BACKUP_BYTES)
    }
    fn encrypted_backup_with_limit(
        &self,
        path: String,
        key: &mut PasswordType,
        force: bool,
        max: u64,
    ) -> Result<(), VaultError> {
        if let PasswordType::Password(p) = key {
            validate_new_password(p).map_err(|e| VaultError::Validation(e.into()))?;
        }
        let destination = Path::new(&path);
        if let VaultStore::File {
            directory,
            filename,
        } = &self.store
            && destination.exists()
            && fs::canonicalize(destination).ok() == fs::canonicalize(directory.join(filename)).ok()
        {
            return Err(VaultError::InvalidInput(
                "backup cannot overwrite the active vault".into(),
            ));
        }
        let mut bytes = persistence::encode_document(&self.data, None)?;
        persistence::validate_encrypted_size(bytes.len(), 9, max, "backup")?;
        let ciphertext = try_encrypt_file_in_place(key, std::mem::take(&mut *bytes))?;
        let mut out = Vec::with_capacity(ciphertext.len() + 9);
        out.extend_from_slice(BACKUP_MAGIC);
        out.push(BACKUP_DOCUMENT_VERSION);
        out.extend(ciphertext);
        persist_private_file(destination, &out, force)
    }
}
pub(crate) fn restore_encrypted_backup(
    path: &str,
    key: &mut PasswordType,
) -> Result<String, VaultError> {
    let bytes = crate::file::read_bounded_file(Path::new(path), MAX_BACKUP_BYTES)
        .map_err(|e| VaultError::Persistence(e.to_string()))?;
    if bytes.len() < 9 || &bytes[..8] != BACKUP_MAGIC || bytes[8] != BACKUP_DOCUMENT_VERSION {
        return Err(VaultError::Validation(
            "unsupported encrypted backup format".into(),
        ));
    }
    let mut candidate = key.clone();
    let plaintext = Zeroizing::new(decrypt_file(&mut candidate, &bytes[9..]).ok_or_else(|| {
        VaultError::Validation("wrong backup password/key or modified backup".into())
    })?);
    let mut data = persistence::decode_document(&plaintext)?;
    // Restores always get an independent identity. Replacing a selected vault is
    // an explicit future operation, never inferred by password equality.
    data.vault_id = rand::random();
    let filename = format!("{}.enc", hex::encode(data.vault_id));
    let vault = Vault {
        data,
        store: VaultStore::File {
            directory: data_dir(),
            filename: filename.clone(),
        },
        metadata: VaultMetadata {
            filename: filename.clone(),
            duo_session: None,
        },
    };
    write_vault_with_key(&vault, &mut candidate)?;
    *key = candidate;
    Ok(filename)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn strong_password() -> PasswordType {
        PasswordType::Password("Cedar-Lantern-Quartz-9274!".into())
    }
    fn source() -> Vault {
        let mut vault = Vault::from_entries(
            vec![VaultEntry {
                id: 9,
                name: "Example".into(),
                password: "backup-secret".into(),
                notes: Some("backup-notes".into()),
                ..Default::default()
            }],
            None,
        );
        vault.set_test_totp(
            9,
            "otpauth://hotp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&counter=5",
        );
        vault.item_mut(9).unwrap().history.push(PasswordRevision {
            password: "old-secret".into(),
            changed: Timestamp::now(),
        });
        vault.item_mut(9).unwrap().lifecycle = Lifecycle::Trashed {
            deleted_at: Timestamp::now(),
        };
        vault
    }
    #[test]
    fn encrypted_backup_restores_complete_items_to_an_independent_vault_identity() {
        crate::file::init_test_data_dir();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.backup");
        let vault = source();
        vault
            .encrypted_backup(path.display().to_string(), &mut strong_password(), false)
            .unwrap();
        let ciphertext = fs::read(&path).unwrap();
        assert!(!String::from_utf8_lossy(&ciphertext).contains("backup-secret"));
        let filename =
            restore_encrypted_backup(path.to_str().unwrap(), &mut strong_password()).unwrap();
        let (_, restored) = persistence::lookup_vault(&mut strong_password(), Some(&filename))
            .unwrap()
            .unwrap();
        assert_eq!(restored.data.items, vault.data.items);
        assert_ne!(restored.data.vault_id, vault.data.vault_id);
        assert_eq!(restored.data.next_item_id, vault.data.next_item_id);
        fs::remove_file(data_dir().join(filename)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn backups_reject_wrong_keys_tampering_unsupported_versions_and_size_limits() {
        crate::file::init_test_data_dir();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.backup");
        let vault = source();
        vault
            .encrypted_backup(path.display().to_string(), &mut strong_password(), false)
            .unwrap();
        let original = fs::read(&path).unwrap();
        assert!(
            restore_encrypted_backup(
                path.to_str().unwrap(),
                &mut PasswordType::Password("Wrong-Master-Quartz-9274!".into())
            )
            .is_err()
        );
        for kind in 0..3 {
            let mut bytes = original.clone();
            match kind {
                0 => bytes[8] = 99,
                1 => {
                    let end = bytes.len() - 1;
                    bytes[end] ^= 1;
                }
                _ => bytes.truncate(5),
            };
            fs::write(&path, bytes).unwrap();
            assert!(
                restore_encrypted_backup(path.to_str().unwrap(), &mut strong_password()).is_err()
            );
        }
        assert!(
            vault
                .encrypted_backup_with_limit(
                    directory.path().join("small.backup").display().to_string(),
                    &mut strong_password(),
                    false,
                    1
                )
                .is_err()
        );
    }
    #[test]
    fn production_argon_parameters_cover_unlock_rekey_backup_restore_and_tampering() {
        use crate::encryption::{PRODUCTION_KDF_PARAMETERS, with_test_kdf_parameters};
        with_test_kdf_parameters(PRODUCTION_KDF_PARAMETERS, || {
            crate::file::init_test_data_dir();
            let directory = tempfile::tempdir().unwrap();
            let mut vault = source();
            vault.item_mut(9).unwrap().lifecycle = Lifecycle::Active;
            vault.metadata.filename = "production.enc".into();
            vault.store = VaultStore::File {
                directory: directory.path().to_owned(),
                filename: "production.enc".into(),
            };
            let mut key = VaultCredentials {
                locked: false,
                keypass: Some(strong_password()),
            };
            write_vault(&vault, &mut key).unwrap();
            let old = fs::read(directory.path().join("production.enc")).unwrap();
            assert_eq!(
                u32::from_be_bytes(old[10..14].try_into().unwrap()),
                PRODUCTION_KDF_PARAMETERS.memory_kib
            );
            assert_eq!(
                persistence::lookup_vault_in(
                    directory.path(),
                    &mut strong_password(),
                    Some("production.enc")
                )
                .unwrap()
                .unwrap()
                .1
                .data,
                vault.data
            );
            vault
                .rekey(
                    &mut key,
                    PasswordType::Password("Maple-Compass-Granite-5842!".into()),
                )
                .unwrap();
            let bytes = fs::read(directory.path().join("production.enc")).unwrap();
            assert!(decrypt_file(&mut strong_password(), &bytes).is_none());
            assert_eq!(
                persistence::lookup_vault_in(
                    directory.path(),
                    &mut PasswordType::Password("Maple-Compass-Granite-5842!".into()),
                    Some("production.enc")
                )
                .unwrap()
                .unwrap()
                .1
                .data,
                vault.data
            );
            let path = directory.path().join("production.backup");
            vault
                .encrypted_backup(path.display().to_string(), &mut strong_password(), false)
                .unwrap();
            let filename =
                restore_encrypted_backup(path.to_str().unwrap(), &mut strong_password()).unwrap();
            let (_, restored) = persistence::lookup_vault(&mut strong_password(), Some(&filename))
                .unwrap()
                .unwrap();
            assert_eq!(restored.data.items, vault.data.items);
            fs::remove_file(data_dir().join(filename)).unwrap();
            let mut tampered = bytes;
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            assert!(
                decrypt_file(
                    &mut PasswordType::Password("Maple-Compass-Granite-5842!".into()),
                    &tampered
                )
                .is_none()
            );
        });
    }
}
