use super::*;

/// Schema 3 adds item organization (tags, favorites) and attachments. A vault
/// that uses none of them is still written as schema 2, so older releases keep
/// reading it; once one is used, older releases refuse the vault instead of
/// silently discarding the new data on their next save.
const DOCUMENT_VERSION: u16 = 3;
const BASELINE_DOCUMENT_VERSION: u16 = 2;
/// Whether this data is saved in the current (not the baseline) schema.
pub(super) fn uses_current_schema(data: &VaultData) -> bool {
    data.items.values().any(Item::needs_current_schema)
}
impl Item {
    fn needs_current_schema(&self) -> bool {
        self.metadata.uses_organization() || !self.attachments.is_empty()
    }
}
#[derive(Debug, Clone, PartialEq)]
pub enum VaultStore {
    Detached,
    Memory,
    File {
        directory: std::path::PathBuf,
        filename: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultDocument {
    schema_version: u16,
    vault_id: [u8; 16],
    next_item_id: u64,
    revision: u64,
    items: Vec<ItemDocument>,
}
#[derive(Serialize)]
struct VaultDocumentRef<'a> {
    schema_version: u16,
    vault_id: [u8; 16],
    next_item_id: u64,
    revision: u64,
    items: DocumentItems<'a>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryDocument {
    name: String,
    username: Option<String>,
    password: SecretString,
    url: Option<String>,
    notes: Option<SecretString>,
    created: Timestamp,
    modified: Timestamp,
}
#[derive(Serialize)]
struct EntryDocumentRef<'a> {
    name: &'a str,
    username: Option<&'a str>,
    password: &'a SecretString,
    url: Option<&'a str>,
    notes: Option<&'a SecretString>,
    created: &'a Timestamp,
    modified: &'a Timestamp,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemDocument {
    id: ItemId,
    revision: u64,
    entry: EntryDocument,
    metadata: EntryMetadata,
    history: Vec<PasswordRevision>,
    authenticator: Option<SecretString>,
    duo: Option<DuoCredentials>,
    lifecycle: Lifecycle,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attachments: Vec<Attachment>,
}
#[derive(Serialize)]
struct ItemDocumentRef<'a> {
    id: ItemId,
    revision: u64,
    entry: EntryDocumentRef<'a>,
    metadata: &'a EntryMetadata,
    history: &'a [PasswordRevision],
    authenticator: Option<&'a SecretString>,
    duo: Option<&'a DuoCredentials>,
    lifecycle: &'a Lifecycle,
    #[serde(skip_serializing_if = "<[Attachment]>::is_empty")]
    attachments: &'a [Attachment],
}
/// Serialize the ordered overlay directly. No full-vault reference map or
/// document vector is needed; the staged records win duplicate IDs.
struct DocumentItems<'a> {
    live: &'a VaultData,
    overlay: Option<(&'a VaultData, &'a HashSet<ItemId>)>,
}
impl Serialize for DocumentItems<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let selected = self.overlay.map(|(_, selected)| selected);
        let staged = self.overlay.map(|(data, _)| &data.items);
        let removed = selected.map_or(0, |ids| {
            ids.iter()
                .filter(|id| self.live.items.contains_key(id))
                .count()
        });
        let added = staged.map_or(0, |items| {
            items
                .keys()
                .filter(|id| {
                    selected.is_some_and(|ids| ids.contains(id))
                        || !self.live.items.contains_key(id)
                })
                .count()
        });
        let mut sequence =
            serializer.serialize_seq(Some(self.live.items.len() - removed + added))?;
        let mut live = self
            .live
            .items
            .iter()
            .filter(|(id, _)| selected.is_none_or(|ids| !ids.contains(id)))
            .peekable();
        let mut staged = staged.into_iter().flat_map(|items| items.iter()).peekable();
        loop {
            let next = match (live.peek(), staged.peek()) {
                (Some((left, _)), Some((right, _))) if left < right => live.next(),
                (Some((left, _)), Some((right, _))) => {
                    if left == right {
                        live.next();
                    }
                    staged.next()
                }
                (Some(_), None) => live.next(),
                (None, Some(_)) => staged.next(),
                (None, None) => break,
            };
            if let Some((id, item)) = next {
                sequence.serialize_element(&ItemDocumentRef::from((*id, item)))?;
            }
        }
        sequence.end()
    }
}
impl<'a> From<(ItemId, &'a Item)> for ItemDocumentRef<'a> {
    fn from((id, item): (ItemId, &'a Item)) -> Self {
        let e = &item.entry;
        Self {
            id,
            revision: item.revision,
            entry: EntryDocumentRef {
                name: &e.name,
                username: e.username.as_deref(),
                password: &e.password,
                url: e.url.as_deref(),
                notes: e.notes.as_ref(),
                created: &e.created,
                modified: &e.modified,
            },
            metadata: &item.metadata,
            history: &item.history,
            authenticator: item.authenticator.as_ref().map(|a| &a.configuration),
            duo: item.duo.as_ref().map(|d| &d.credentials),
            lifecycle: &item.lifecycle,
            attachments: &item.attachments,
        }
    }
}
pub(super) fn encode_document(
    data: &VaultData,
    overlay: Option<(&VaultData, &HashSet<ItemId>)>,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut bytes = SecretBuffer::default();
    write_document(&mut bytes, data, overlay)?;
    Ok(bytes.into_inner())
}
fn write_document(
    out: &mut SecretBuffer,
    data: &VaultData,
    overlay: Option<(&VaultData, &HashSet<ItemId>)>,
) -> Result<(), VaultError> {
    let (next_item_id, revision) = overlay
        .map_or((data.next_item_id, data.revision), |(staged, _)| {
            (staged.next_item_id, staged.revision)
        });
    let current = data
        .items
        .values()
        .chain(
            overlay
                .into_iter()
                .flat_map(|(staged, _)| staged.items.values()),
        )
        .any(Item::needs_current_schema);
    let document = VaultDocumentRef {
        schema_version: if current {
            DOCUMENT_VERSION
        } else {
            BASELINE_DOCUMENT_VERSION
        },
        vault_id: data.vault_id,
        next_item_id,
        revision,
        items: DocumentItems {
            live: data,
            overlay,
        },
    };
    // Named fields preserve the durable schema independently of Rust field order.
    rmp_serde::encode::write_named(out, &document)
        .map_err(|e| VaultError::Persistence(format!("could not encode vault document: {e}")))
}
pub(super) fn decode_document(bytes: &[u8]) -> Result<VaultData, VaultError> {
    let document: VaultDocument = rmp_serde::from_slice(bytes).map_err(|e| {
        VaultError::Validation(format!("authenticated vault document is invalid: {e}"))
    })?;
    if !(BASELINE_DOCUMENT_VERSION..=DOCUMENT_VERSION).contains(&document.schema_version) {
        return Err(VaultError::Validation("unsupported vault document schema; export development vaults with their original binary".into()));
    }
    if document.vault_id == [0; 16] {
        return Err(VaultError::Validation(
            "vault document identity cannot be zero".into(),
        ));
    }
    if document.revision > MAX_ITEM_ID {
        return Err(VaultError::Validation(
            "vault revision exceeds the supported range".into(),
        ));
    }
    let mut data = VaultData {
        items: BTreeMap::new(),
        vault_id: document.vault_id,
        next_item_id: document.next_item_id,
        revision: document.revision,
    };
    for item in document.items {
        let id = item.id.public()?;
        if item.revision == 0 || item.revision > MAX_ITEM_ID {
            return Err(VaultError::Validation(
                "item revision must be a positive safe integer".into(),
            ));
        }
        if let Some(ref credentials) = item.duo {
            crate::duo::validate_credentials(credentials)?;
        }
        attachments::check_stored(&item.attachments)?;
        let authenticator = item
            .authenticator
            .as_ref()
            .map(|a| Authenticator::parse(a))
            .transpose()?;
        let e = item.entry;
        let entry = VaultEntry {
            id,
            name: e.name,
            username: e.username,
            password: e.password,
            url: e.url,
            notes: e.notes,
            created: e.created,
            modified: e.modified,
        };
        let value = Item {
            revision: item.revision,
            history: item.history,
            authenticator,
            duo: item.duo.map(|credentials| DuoRecord {
                credentials,
                review_key: None,
            }),
            lifecycle: item.lifecycle,
            attachments: item.attachments,
            ..Item::new(entry, item.metadata)
        };
        if data.items.insert(item.id, value).is_some() {
            return Err(VaultError::Validation(
                "duplicate item ID in vault document".into(),
            ));
        }
    }
    let highest = data.items.keys().next_back().map_or(0, |id| id.0);
    if data.next_item_id == 0 || data.next_item_id <= highest || data.next_item_id > MAX_ITEM_ID + 1
    {
        return Err(VaultError::Validation(
            "invalid next item ID in vault document".into(),
        ));
    }
    Ok(data)
}
impl VaultStore {
    pub(super) fn commit_overlay(
        &self,
        live: &VaultData,
        staged: &VaultData,
        selected: &HashSet<ItemId>,
        credentials: &mut VaultCredentials,
    ) -> Result<(), VaultError> {
        if !matches!(self, Self::Memory) && credentials.is_locked() {
            return Err(VaultError::Locked);
        }
        self.persist(
            live,
            Some((staged, selected)),
            credentials,
            active_vault_limit(),
        )
    }
    /// Confirm a later save could write its replacement file, without
    /// rewriting the vault: a fresh encryption nonce would change the file
    /// digest and make cloud sync see a local edit. The probe is as large as
    /// the vault plus headroom and is flushed to disk, so a nearly full disk
    /// fails here, before work that cannot be repeated (a Duo activation).
    pub(super) fn check_writable(&self) -> Result<(), VaultError> {
        const HEADROOM: u64 = 64 * 1024;
        match self {
            Self::Memory => Ok(()),
            Self::Detached => Err(VaultError::Persistence("vault has no durable store".into())),
            Self::File {
                directory,
                filename,
            } => run_blocking_io(|| {
                let failed = |e: std::io::Error| {
                    VaultError::Persistence(format!("vault directory is not writable: {e}"))
                };
                let mut left = fs::metadata(directory.join(filename))
                    .map_or(0, |metadata| metadata.len())
                    + HEADROOM;
                let mut probe = NamedTempFile::new_in(directory).map_err(failed)?;
                let chunk = [0u8; 64 * 1024];
                while left > 0 {
                    let len = chunk.len().min(usize::try_from(left).unwrap_or(usize::MAX));
                    probe.write_all(&chunk[..len]).map_err(failed)?;
                    left -= len as u64;
                }
                probe.as_file().sync_all().map_err(failed)
            }),
        }
    }
    /// Memory stores keep nothing durable; a detached handle cannot be written.
    fn persist(
        &self,
        data: &VaultData,
        overlay: Option<(&VaultData, &HashSet<ItemId>)>,
        credentials: &mut VaultCredentials,
        max_bytes: u64,
    ) -> Result<(), VaultError> {
        match self {
            Self::Memory => Ok(()),
            Self::Detached => Err(VaultError::Persistence("vault has no durable store".into())),
            Self::File {
                directory,
                filename,
            } => persist_document(directory, filename, data, overlay, credentials, max_bytes),
        }
    }
}
fn active_vault_limit() -> u64 {
    #[cfg(test)]
    {
        TEST_MAX_VAULT_BYTES.get()
    }
    #[cfg(not(test))]
    {
        MAX_VAULT_BYTES
    }
}
impl Vault {
    pub fn rekey(
        &mut self,
        credentials: &mut VaultCredentials,
        new_key: PasswordType,
    ) -> Result<(), VaultError> {
        if !matches!(self.store, VaultStore::Memory) && credentials.is_locked() {
            return Err(VaultError::Locked);
        }
        if let PasswordType::Password(password) = &new_key {
            validate_new_password(password).map_err(|e| VaultError::Validation(e.into()))?;
        }
        let generated = match &new_key {
            PasswordType::Key(path) => Some(new_key_file_path(path)?),
            _ => None,
        };
        if let Some(path) = &generated {
            if path.exists() {
                return Err(VaultError::Conflict("new key file already exists".into()));
            }
            if let PasswordType::Key(key) = &new_key {
                let mut material = try_keyfile_master_key(key, true)?;
                material.zeroize();
            }
        }
        let result = self.rekey_credentials(credentials, VaultCredentials::from(new_key));
        if result.as_ref().is_err_and(|e| !e.committed())
            && let Some(path) = generated
        {
            let _ = fs::remove_file(path);
        }
        result
    }
    pub(crate) fn rekey_credentials(
        &mut self,
        credentials: &mut VaultCredentials,
        mut replacement: VaultCredentials,
    ) -> Result<(), VaultError> {
        if !matches!(self.store, VaultStore::Memory) && credentials.is_locked() {
            return Err(VaultError::Locked);
        }
        let next_revision = next_revision(self.data.revision)
            .ok_or_else(|| VaultError::Conflict("vault revision exhausted".into()))?;
        let staged = VaultData {
            items: BTreeMap::new(),
            vault_id: self.data.vault_id,
            next_item_id: self.data.next_item_id,
            revision: next_revision,
        };
        let result =
            self.store
                .commit_overlay(&self.data, &staged, &HashSet::new(), &mut replacement);
        if result.as_ref().map_or_else(|e| e.committed(), |_| true) {
            self.data.revision = next_revision;
            *credentials = std::mem::take(&mut replacement);
        }
        result
    }
}
/// List opaque vault IDs without opening or decrypting their contents.
pub fn list_vaults() -> Result<Vec<String>, VaultError> {
    list_vaults_in(&data_dir())
}

fn list_vaults_in(directory: &Path) -> Result<Vec<String>, VaultError> {
    crate::file::list_vault_files(directory).map_err(|error| {
        VaultError::Persistence(format!("could not list vault directory: {error}"))
    })
}

pub fn validate_vault_filename(name: &str) -> Result<(), VaultError> {
    if name.is_empty()
        || !name.ends_with(".enc")
        || name.contains(['/', '\\', ':', '\0'])
        || Path::new(name).components().count() != 1
    {
        return Err(VaultError::InvalidInput(
            "vault ID must be a single .enc filename from `pm vaults`".into(),
        ));
    }
    Ok(())
}

pub(super) fn lookup_vault(
    key_pass: &mut VaultCredentials,
    selected: Option<&str>,
) -> Result<Option<(String, Vault)>, VaultError> {
    lookup_vault_in(&data_dir(), key_pass, selected)
}

pub(super) fn lookup_vault_in(
    directory: &Path,
    key_pass: &mut VaultCredentials,
    selected: Option<&str>,
) -> Result<Option<(String, Vault)>, VaultError> {
    // Read the key file before the vault so its errors stay specific; the
    // derived key is reused for decryption instead of reading the file again.
    let keyfile_master = if let VaultCredentials::Unlock(PasswordType::Key(key)) = &*key_pass {
        Some(Zeroizing::new(
            try_keyfile_master_key(key, false).map_err(VaultError::Persistence)?,
        ))
    } else {
        None
    };
    let filename = match selected {
        Some(name) => {
            validate_vault_filename(name)?;
            name.to_owned()
        }
        None => {
            let names = list_vaults_in(directory)?;
            match names.as_slice() {
                [] => return Ok(None),
                [name] => name.clone(),
                many if keyfile_master.is_some() => {
                    // A key file opens exactly one vault; find it instead of asking.
                    // A wrong key is expected for the others, but any other problem
                    // (unreadable file, identity mismatch, damage) is the real answer.
                    let mut other_problem = None;
                    for name in many {
                        let mut candidate = key_pass.clone();
                        match lookup_vault_in(directory, &mut candidate, Some(name)) {
                            Ok(Some(found)) => {
                                *key_pass = candidate;
                                return Ok(Some(found));
                            }
                            Err(error)
                                if other_problem.is_none()
                                    && !error.to_string().contains("incorrect password/key") =>
                            {
                                other_problem = Some(error);
                            }
                            _ => {}
                        }
                    }
                    return Err(other_problem.unwrap_or_else(|| {
                        VaultError::Validation(
                            "this key file does not open any vault on this device".into(),
                        )
                    }));
                }
                _ => {
                    return Err(VaultError::InvalidInput(
                        "several vaults exist; choose which one to open".into(),
                    ));
                }
            }
        }
    };
    let path = directory.join(&filename);
    let metadata = fs::symlink_metadata(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            VaultError::NotFound(format!("vault {filename:?} does not exist"))
        } else {
            VaultError::Persistence(e.to_string())
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(VaultError::Validation(
            "vault must be a regular file".into(),
        ));
    }
    let contents = crate::file::read_bounded_file(&path, MAX_VAULT_BYTES)
        .map_err(|e| VaultError::Persistence(format!("could not read vault {filename:?}: {e}")))?;
    crate::encryption::validate_vault_header(&contents)
        .map_err(|e| VaultError::Validation(e.into()))?;
    let mut candidate = keyfile_master
        .as_ref()
        .and_then(|master| crate::encryption::keyfile_session(&contents, master))
        .unwrap_or_else(|| key_pass.clone());
    let plaintext = decrypt_file(&mut candidate, &contents).ok_or_else(|| {
        VaultError::Validation("incorrect password/key or modified encrypted contents".into())
    })?;
    let data = decode_document(&plaintext)?;
    crate::cloud::verify_identity(&path, data.vault_id).map_err(VaultError::Validation)?;
    *key_pass = candidate;
    let vault = Vault::file(data, directory.to_owned(), filename.clone());
    Ok(Some((filename, vault)))
}

#[cfg(test)]
thread_local! {
    static WRITE_FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

fn before_vault_replace() -> Result<(), VaultError> {
    #[cfg(test)]
    if WRITE_FAULT.get() == 3 {
        std::process::exit(71);
    }
    #[cfg(test)]
    if WRITE_FAULT.get() == 1 {
        return Err(VaultError::Persistence(
            "injected failure before replacement".into(),
        ));
    }
    Ok(())
}

fn sync_vault_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if WRITE_FAULT.get() == 4 {
        std::process::exit(72);
    }
    #[cfg(test)]
    if WRITE_FAULT.get() == 2 {
        return Err(std::io::Error::other("injected failure after replacement"));
    }
    sync_parent(path)
}

#[cfg(test)]
pub(crate) fn with_write_fault<T>(fault: u8, operation: impl FnOnce() -> T) -> T {
    struct Reset(u8);
    impl Drop for Reset {
        fn drop(&mut self) {
            WRITE_FAULT.set(self.0);
        }
    }
    let _reset = Reset(WRITE_FAULT.replace(fault));
    operation()
}

pub(crate) fn create_vault(
    vault: &mut Option<Vault>,
    credentials: &mut VaultCredentials,
    lock: bool,
) -> Result<(), VaultError> {
    if credentials.is_locked() {
        return Err(VaultError::Locked);
    }
    if let VaultCredentials::Unlock(PasswordType::Password(password)) = credentials {
        validate_new_password(password).map_err(|e| VaultError::Validation(e.into()))?;
    }
    let generated = match credentials {
        VaultCredentials::Unlock(PasswordType::Key(path)) => Some(new_key_file_path(path)?),
        _ => None,
    };
    if generated.is_some()
        && let VaultCredentials::Unlock(PasswordType::Key(key)) = &*credentials
    {
        let mut material = try_keyfile_master_key(key, true)?;
        material.zeroize();
    }
    let mut data = VaultData::with_random_id();
    let filename = loop {
        let name = format!("{}.enc", hex::encode(data.vault_id));
        if !data_dir().join(&name).exists() {
            break name;
        }
        data.vault_id = rand::random();
    };
    let created = Vault::file(data, data_dir(), filename);
    let result = write_vault(&created, credentials);
    if let Err(error) = result {
        if !error.committed()
            && let Some(path) = generated
        {
            let _ = fs::remove_file(path);
        }
        *credentials = VaultCredentials::Locked;
        return Err(error);
    }
    if lock {
        *credentials = VaultCredentials::Locked;
    } else {
        *vault = Some(created);
    }
    Ok(())
}
pub(super) fn write_vault(
    vault: &Vault,
    credentials: &mut VaultCredentials,
) -> Result<(), VaultError> {
    if !matches!(vault.store, VaultStore::Memory) && credentials.is_locked() {
        return Err(VaultError::Locked);
    }
    write_vault_with_key(vault, credentials)
}
pub(super) fn write_vault_with_key(
    vault: &Vault,
    key: &mut VaultCredentials,
) -> Result<(), VaultError> {
    vault
        .store
        .persist(&vault.data, None, key, active_vault_limit())
}
#[cfg(test)]
thread_local! {static TEST_MAX_VAULT_BYTES:std::cell::Cell<u64>=const {std::cell::Cell::new(MAX_VAULT_BYTES)};}
#[cfg(test)]
fn write_vault_with_limit(
    vault: &Vault,
    key: &mut VaultCredentials,
    max_bytes: u64,
) -> Result<(), VaultError> {
    vault.store.persist(&vault.data, None, key, max_bytes)
}

/// Encrypt a candidate without advancing credentials until replacement commits.
fn persist_document(
    directory: &Path,
    filename: &str,
    data: &VaultData,
    overlay: Option<(&VaultData, &HashSet<ItemId>)>,
    credentials: &mut VaultCredentials,
    max_bytes: u64,
) -> Result<(), VaultError> {
    // The current file size (a non-secret length) sizes the buffer, so a
    // typical save serializes and encrypts without reallocating plaintext.
    let previous = fs::metadata(directory.join(filename)).map_or(0, |m| m.len().min(max_bytes));
    let previous = usize::try_from(previous).unwrap_or(0);
    let mut plaintext =
        crate::encryption::framed_plaintext(previous.saturating_add(previous / 16 + 4096));
    write_document(&mut plaintext, data, overlay)?;
    validate_encrypted_size(
        crate::encryption::framed_payload_len(&plaintext),
        0,
        max_bytes,
        "vault",
    )?;
    let mut candidate = credentials.clone();
    let ciphertext = crate::encryption::try_encrypt_framed(&mut candidate, plaintext)?;
    let result = persist_ciphertext(directory, filename, &ciphertext);
    if result.as_ref().map_or_else(|e| e.committed(), |_| true) {
        *credentials = candidate;
    }
    result
}

pub(crate) fn persist_ciphertext(
    directory: &Path,
    filename: &str,
    txt: &[u8],
) -> Result<(), VaultError> {
    validate_vault_filename(filename)?;
    let file_path = directory.join(filename);
    run_blocking_io(|| {
        let mut temporary = NamedTempFile::new_in(directory).map_err(|e| {
            VaultError::Persistence(format!("could not create vault temp file: {e}"))
        })?;
        set_private_perms(temporary.path()).map_err(|e| {
            VaultError::Persistence(format!("could not protect vault temp file: {e}"))
        })?;
        temporary.write_all(txt).map_err(|e| {
            VaultError::Persistence(format!("could not write encrypted vault: {e}"))
        })?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|e| VaultError::Persistence(format!("could not sync encrypted vault: {e}")))?;
        before_vault_replace()?;
        temporary.persist(&file_path).map_err(|e| {
            VaultError::Persistence(format!(
                "could not atomically replace vault file: {}",
                e.error
            ))
        })?;
        sync_vault_parent(&file_path).map_err(|e| {
            VaultError::Durability(format!(
                "vault replacement committed, but durability could not be confirmed: {e}; \
                 the new state is active; do not blindly retry this operation"
            ))
        })?;
        Ok(())
    })
}

pub(super) fn validate_encrypted_size(
    plaintext_bytes: usize,
    prefix_bytes: usize,
    max_bytes: u64,
    label: &str,
) -> Result<(), VaultError> {
    let encrypted_bytes = plaintext_bytes
        .checked_add(crate::encryption::ENCRYPTED_FILE_OVERHEAD)
        .and_then(|size| size.checked_add(prefix_bytes));
    if encrypted_bytes.is_none_or(|size| size as u64 > max_bytes) {
        return Err(VaultError::Validation(format!(
            "{label} exceeds the {max_bytes} byte encrypted-file limit; reduce its size before saving"
        )));
    }
    Ok(())
}

// Buffered streaming without leaving plaintext in an ordinary BufWriter allocation.
struct PrivateWriter<'a> {
    file: &'a mut fs::File,
    buffer: Zeroizing<Vec<u8>>,
}
impl Write for PrivateWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        const CAPACITY: usize = 64 * 1024;
        if self.buffer.len().saturating_add(bytes.len()) > CAPACITY {
            self.flush()?;
        }
        if bytes.len() >= CAPACITY {
            self.file.write_all(bytes)?;
        } else {
            self.buffer.extend_from_slice(bytes);
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.write_all(&self.buffer)?;
        self.buffer.zeroize();
        self.file.flush()
    }
}

pub(super) fn persist_private_stream(
    path: &Path,
    force: bool,
    write: impl FnOnce(&mut dyn Write) -> Result<(), VaultError>,
) -> Result<(), VaultError> {
    crate::file::validate_external_output_path(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::InvalidInput {
            VaultError::InvalidInput(error.to_string())
        } else {
            VaultError::Persistence(format!("could not validate destination: {error}"))
        }
    })?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    run_blocking_io(|| {
        let mut temporary = NamedTempFile::new_in(parent).map_err(|error| {
            VaultError::Persistence(format!("could not create private temp file: {error}"))
        })?;
        set_private_perms(temporary.path()).map_err(|error| {
            VaultError::Persistence(format!("could not protect private temp file: {error}"))
        })?;
        let mut writer = PrivateWriter {
            file: temporary.as_file_mut(),
            buffer: Zeroizing::new(Vec::with_capacity(64 * 1024)),
        };
        write(&mut writer)?;
        writer
            .flush()
            .map_err(|e| VaultError::Persistence(format!("could not flush private file: {e}")))?;
        drop(writer);
        temporary.as_file().sync_all().map_err(|error| {
            VaultError::Persistence(format!("could not write private file: {error}"))
        })?;
        if force {
            temporary.persist(path).map_err(|error| {
                VaultError::Persistence(format!("could not replace private file: {}", error.error))
            })?;
        } else {
            temporary.persist_noclobber(path).map_err(|error| {
                if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                    VaultError::Conflict(format!(
                        "destination file {:?} already exists; use --force to replace it",
                        path
                    ))
                } else {
                    VaultError::Persistence(format!(
                        "could not create private file: {}",
                        error.error
                    ))
                }
            })?;
        }
        sync_parent(path).map_err(|error| {
            VaultError::Durability(format!("file replacement committed, but durability could not be confirmed: {error}; do not blindly retry"))
        })?;
        Ok(())
    })
}

pub(crate) fn unlock_selected_vault(
    key_pass: &mut VaultCredentials,
    selected: Option<&str>,
) -> Result<Vault, VaultError> {
    if key_pass.is_locked() {
        return Err(VaultError::Locked);
    }
    let (_, vault) = lookup_vault(key_pass, selected)?.ok_or_else(|| VaultError::Validation(
        "no matching vault: incorrect password/key, no vault exists, or encrypted contents were modified; use `pm vaults` and `pm unlock --vault-file ID` to inspect a specific vault".into()
    ))?;

    Ok(vault)
}

pub(crate) fn delete_vault(
    key: PasswordType,
    keep_key: bool,
    selected: Option<&str>,
) -> Result<(), VaultError> {
    let data = data_dir();
    let key_to_remove = match &key {
        PasswordType::Key(path) if !keep_key => Some(path.clone()),
        _ => None,
    };
    if let PasswordType::Key(key_path) = &key
        && !key_file_path(key_path)?.is_file()
    {
        return Err(("key file does not exist or is not a regular file".to_string()).into());
    }
    let (filename, mut vault) = lookup_vault(&mut key.into(), selected)?
        .ok_or_else(|| "could not delete vault (is the key correct?)".to_string())?;
    vault.zeroize();
    fs::remove_file(data.join(filename)).map_err(|e| {
        VaultError::Persistence(format!("could not delete vault (is the key correct?): {e}"))
    })?;
    if let Some(mut key) = key_to_remove {
        fs::remove_file(key_file_path(&key)?).map_err(|e| {
            VaultError::Persistence(format!(
                "vault deleted, but could not delete its key file: {e}"
            ))
        })?;
        key.zeroize();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::test::{key as session, persist_fixture};
    #[test]
    fn overlay_preserves_document_bytes_for_replacements_deletions_and_insertions() {
        let entry = |id, name: &str| VaultEntry {
            id,
            name: name.into(),
            ..Default::default()
        };
        let live = Vault::from_entries(
            vec![entry(1, "old"), entry(2, "deleted"), entry(4, "last")],
            None,
        );
        let mut staged =
            Vault::from_entries(vec![entry(1, "replacement"), entry(3, "inserted")], None);
        staged.data.next_item_id = 5;
        staged.data.revision = 9;
        let selected = HashSet::from([ItemId::from_public(2).unwrap()]);
        let mut expected = live.data.clone();
        expected.items.remove(&ItemId::from_public(2).unwrap());
        expected.items.extend(staged.data.items.clone());
        expected.next_item_id = 5;
        expected.revision = 9;
        let bytes = encode_document(&live.data, Some((&staged.data, &selected))).unwrap();
        assert_eq!(*bytes, *encode_document(&expected, None).unwrap());
        assert_eq!(decode_document(&bytes).unwrap(), expected);
        // The serializer must keep the existing named-field/vector wire shape.
        let document: VaultDocument = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(*bytes, rmp_serde::to_vec_named(&document).unwrap());
    }
    #[test]
    fn streaming_overlays_keep_the_collected_wire_shape_for_every_small_overlay() {
        let live = Vault::from_entries(
            (1..=4)
                .map(|id| VaultEntry {
                    id,
                    name: format!("live-{id}"),
                    ..Default::default()
                })
                .collect(),
            None,
        );
        for mask in 0..16 {
            let selected: HashSet<_> = (1..=4)
                .filter(|id| mask & (1 << (id - 1)) != 0)
                .map(|id| ItemId::from_public(id).unwrap())
                .collect();
            for staged_mask in 0..16 {
                let staged = Vault::from_entries(
                    (2..=5)
                        .filter(|id| staged_mask & (1 << (id - 2)) != 0)
                        .map(|id| VaultEntry {
                            id,
                            name: format!("staged-{id}"),
                            ..Default::default()
                        })
                        .collect(),
                    None,
                );
                let bytes = encode_document(&live.data, Some((&staged.data, &selected))).unwrap();
                let document: VaultDocument = rmp_serde::from_slice(&bytes).unwrap();
                assert_eq!(*bytes, rmp_serde::to_vec_named(&document).unwrap());
                let mut expected = live.data.items.clone();
                expected.retain(|id, _| !selected.contains(id));
                expected.extend(staged.data.items.clone());
                let ids: Vec<_> = document.items.iter().map(|item| item.id).collect();
                assert_eq!(ids, expected.keys().copied().collect::<Vec<_>>());
                assert_eq!(
                    document
                        .items
                        .iter()
                        .map(|item| item.entry.name.as_str())
                        .collect::<Vec<_>>(),
                    expected
                        .values()
                        .map(|item| item.entry.name.as_str())
                        .collect::<Vec<_>>()
                );
            }
        }
    }
    fn stored() -> (tempfile::TempDir, Vault, VaultCredentials) {
        persist_fixture(
            Vault::from_entries(
                vec![VaultEntry {
                    id: 1,
                    name: "Example".into(),
                    password: "before".into(),
                    ..Default::default()
                }],
                None,
            ),
            "vault.enc",
        )
    }
    #[test]
    fn size_limits_include_authenticated_encryption_and_backup_overhead() {
        let overhead = crate::encryption::ENCRYPTED_FILE_OVERHEAD as u64;
        assert!(validate_encrypted_size(10, 0, overhead + 10, "vault").is_ok());
        assert!(validate_encrypted_size(10, 0, overhead + 9, "vault").is_err());
        assert!(validate_encrypted_size(10, 9, overhead + 19, "backup").is_ok());
        assert!(validate_encrypted_size(10, 9, overhead + 18, "backup").is_err());
        assert!(validate_encrypted_size(usize::MAX, 9, u64::MAX, "backup").is_err());
    }
    #[test]
    fn oversized_staged_change_and_rekey_leave_file_key_and_live_state_unchanged() {
        let (directory, mut vault, mut credentials) = stored();
        let before = vault.clone();
        let bytes = fs::read(directory.path().join("vault.enc")).unwrap();
        struct Restore(u64);
        impl Drop for Restore {
            fn drop(&mut self) {
                TEST_MAX_VAULT_BYTES.set(self.0);
            }
        }
        let _restore = Restore(TEST_MAX_VAULT_BYTES.replace(bytes.len() as u64));
        let result = vault.transaction(TransactionScope::Entry(1), &mut credentials, |v| {
            v.item_mut(1).unwrap().entry.notes = Some("x".repeat(1024).into());
            Ok((true, ()))
        });
        assert!(matches!(result, Err(VaultError::Validation(_))));
        assert_eq!(vault, before);
        assert_eq!(fs::read(directory.path().join("vault.enc")).unwrap(), bytes);
        let mut replacement =
            VaultCredentials::from(PasswordType::Password("Cedar-Lantern-Quartz-9274!".into()));
        assert!(write_vault_with_limit(&vault, &mut replacement, 1).is_err());
        assert!(matches!(
            replacement,
            VaultCredentials::Unlock(PasswordType::Password(_))
        ));
        write_vault_with_limit(&vault, &mut credentials, bytes.len() as u64).unwrap();
    }
    #[test]
    fn rekey_adopts_new_key_only_after_atomic_replace_including_uncertain_durability() {
        let (directory, mut vault, mut credentials) = stored();
        let key_path = directory.path().join("replacement.key");
        let replacement = PasswordType::Key(key_path.display().to_string());
        let before = fs::read(directory.path().join("vault.enc")).unwrap();
        let error =
            with_write_fault(1, || vault.rekey(&mut credentials, replacement.clone())).unwrap_err();
        assert!(!error.committed());
        assert!(!key_path.exists());
        assert_eq!(
            fs::read(directory.path().join("vault.enc")).unwrap(),
            before
        );
        let error =
            with_write_fault(2, || vault.rekey(&mut credentials, replacement.clone())).unwrap_err();
        assert!(error.committed());
        assert!(key_path.exists());
        let after = fs::read(directory.path().join("vault.enc")).unwrap();
        assert!(decrypt_file(&mut session(42), &after).is_none());
        let plaintext = decrypt_file(&mut replacement.clone().into(), &after).unwrap();
        assert_eq!(decode_document(&plaintext).unwrap(), vault.data);
        assert!(decrypt_file(&mut credentials, &after).is_some());
        write_vault(&vault, &mut credentials).unwrap();
    }
    #[test]
    fn selected_lookup_checks_structure_authentication_and_independent_document_schema() {
        let (directory, vault, _) = stored();
        let valid = fs::read(directory.path().join("vault.enc")).unwrap();
        fs::write(directory.path().join("broken.enc"), b"broken").unwrap();
        assert!(
            lookup_vault_in(directory.path(), &mut session(42), None).is_err(),
            "selection is required with multiple identities"
        );
        assert_eq!(
            lookup_vault_in(directory.path(), &mut session(42), Some("vault.enc"))
                .unwrap()
                .unwrap()
                .1
                .data,
            vault.data
        );
        assert!(lookup_vault_in(directory.path(), &mut session(43), Some("vault.enc")).is_err());
        assert!(lookup_vault_in(directory.path(), &mut session(42), Some("broken.enc")).is_err());
        for name in [
            "../vault.enc",
            "/vault.enc",
            "x\\vault.enc",
            "C:vault.enc",
            "vault",
            "",
        ] {
            assert!(lookup_vault_in(directory.path(), &mut session(42), Some(name)).is_err());
        }
        let mut tampered = valid.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        fs::write(directory.path().join("tampered.enc"), tampered).unwrap();
        assert!(lookup_vault_in(directory.path(), &mut session(42), Some("tampered.enc")).is_err());
        let mut future = valid;
        future[8] = 99;
        fs::write(directory.path().join("future.enc"), future).unwrap();
        assert!(
            lookup_vault_in(directory.path(), &mut session(42), Some("future.enc"))
                .unwrap_err()
                .to_string()
                .contains("unsupported")
        );
        let mut document: serde_json::Value =
            rmp_serde::from_slice(&encode_document(&vault.data, None).unwrap()).unwrap();
        document["schema_version"] = 99.into();
        let future = try_encrypt_file_in_place(
            &mut session(42),
            rmp_serde::to_vec_named(&document).unwrap(),
        )
        .unwrap();
        fs::write(directory.path().join("schema.enc"), future).unwrap();
        assert!(
            lookup_vault_in(directory.path(), &mut session(42), Some("schema.enc"))
                .unwrap_err()
                .to_string()
                .contains("schema")
        );
    }
    #[test]
    fn document_validation_rejects_duplicates_zero_ids_unsafe_counters_and_invalid_authenticators()
    {
        let (_directory, vault, _) = stored();
        let bytes = encode_document(&vault.data, None).unwrap();
        let original: serde_json::Value = rmp_serde::from_slice(&bytes).unwrap();
        for kind in 0..5 {
            let mut doc = original.clone();
            match kind {
                0 => {
                    let item = doc["items"][0].clone();
                    doc["items"].as_array_mut().unwrap().push(item);
                }
                1 => doc["items"][0]["id"] = 0.into(),
                2 => doc["next_item_id"] = 1.into(),
                3 => doc["items"][0]["authenticator"] = "invalid seed".into(),
                _ => doc["items"][0]["entry"]["created"] = "yesterday".into(),
            }
            assert!(
                decode_document(&rmp_serde::to_vec_named(&doc).unwrap()).is_err(),
                "invalid document {kind}"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn encrypted_files_are_private_and_symlinks_are_never_selected() {
        use std::os::unix::fs::PermissionsExt;
        let (directory, _, _) = stored();
        let path = directory.path().join("vault.enc");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::os::unix::fs::symlink(&path, directory.path().join("link.enc")).unwrap();
        fs::create_dir(directory.path().join("directory.enc")).unwrap();
        assert_eq!(list_vaults_in(directory.path()).unwrap(), vec!["vault.enc"]);
        assert!(lookup_vault_in(directory.path(), &mut session(42), Some("link.enc")).is_err());
    }
    #[test]
    fn rekey_process_crash_helper() {
        let Ok(directory) = std::env::var("PM_TEST_REKEY_CRASH_DATA") else {
            return;
        };
        let key_path = std::env::var("PM_TEST_REKEY_CRASH_KEY").unwrap();
        let fault = std::env::var("PM_TEST_REKEY_CRASH_STAGE")
            .unwrap()
            .parse()
            .unwrap();
        let (_, mut vault) =
            lookup_vault_in(Path::new(&directory), &mut session(42), Some("vault.enc"))
                .unwrap()
                .unwrap();
        let mut credentials = session(42);
        with_write_fault(fault, || {
            vault.rekey(&mut credentials, PasswordType::Key(key_path))
        })
        .unwrap();
        panic!("crash injection did not exit");
    }
    #[test]
    fn abrupt_process_exit_during_rekey_leaves_one_complete_old_or_new_document() {
        for (fault, code) in [(3, 71), (4, 72)] {
            let (directory, vault, _) = stored();
            let original = fs::read(directory.path().join("vault.enc")).unwrap();
            let key_path = directory.path().join("replacement.key");
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "vault::persistence::tests::rekey_process_crash_helper",
                ])
                .env("PM_TEST_REKEY_CRASH_DATA", directory.path())
                .env("PM_TEST_REKEY_CRASH_KEY", &key_path)
                .env("PM_TEST_REKEY_CRASH_STAGE", fault.to_string())
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(code),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(list_vaults_in(directory.path()).unwrap(), vec!["vault.enc"]);
            let reopened = if fault == 3 {
                assert_eq!(
                    fs::read(directory.path().join("vault.enc")).unwrap(),
                    original
                );
                assert!(
                    lookup_vault_in(
                        directory.path(),
                        &mut PasswordType::Key(key_path.display().to_string()).into(),
                        Some("vault.enc")
                    )
                    .is_err()
                );
                lookup_vault_in(directory.path(), &mut session(42), Some("vault.enc"))
            } else {
                assert!(
                    lookup_vault_in(directory.path(), &mut session(42), Some("vault.enc")).is_err()
                );
                lookup_vault_in(
                    directory.path(),
                    &mut PasswordType::Key(key_path.display().to_string()).into(),
                    Some("vault.enc"),
                )
            };
            let reopened = reopened.unwrap().unwrap().1;
            assert_eq!(reopened.data.items, vault.data.items);
            assert_eq!(
                reopened.data.revision,
                vault.data.revision + u64::from(fault == 4)
            );
        }
    }
}
