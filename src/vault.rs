#[cfg(test)]
use crate::encryption::{PRODUCTION_KDF_PARAMETERS, try_encrypt_file, with_test_kdf_parameters};
use crate::{
    clipboard::copy_in_background,
    encryption::{
        decrypt_file, try_encrypt_file_in_place, try_gen_master_key, validate_new_password,
    },
    file::{
        data_dir, file_exists, key_file_path, new_key_file_path, set_private_perms, sync_parent,
    },
    protocol::ResponseCode,
    server::{ServerInfo, respond, respond_with_code},
    types::{
        AuditOptions, ConflictPolicy, CustomField, EntryUpdate, ItemKind, ListOptions,
        PasswordEntry, PasswordType, SearchFilter, SortField, Target, TypedEntry, TypedUpdate,
        UpdateArgs,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha1::{Digest, Sha1};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, read},
    io::{Read, Write},
    path::Path,
};
use tempfile::NamedTempFile;
use tokio::net::TcpStream;
use totp_rs::{Builder as TotpBuilder, Secret as TotpSecret, Totp, TotpError};
use zeroize::{Zeroize, Zeroizing};

mod audit;
#[cfg(test)]
use audit::parse_pwned_range;
use audit::{breached_hashes, password_hash};
mod import;
use import::{import_csv, import_json};

#[derive(Serialize, Deserialize, Default, PartialEq, Clone)]
pub struct VaultEntry {
    pub id: usize,
    pub name: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub created: String,
    pub modified: String,
}

impl std::fmt::Debug for VaultEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VaultEntry")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("url", &self.url)
            .field("notes", &self.notes.as_ref().map(|_| "<redacted>"))
            .field("created", &self.created)
            .field("modified", &self.modified)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Default, PartialEq, Clone)]
pub struct PasswordRevision {
    pub entry_id: usize,
    pub password: String,
    pub changed: String,
}

impl std::fmt::Debug for PasswordRevision {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PasswordRevision")
            .field("entry_id", &self.entry_id)
            .field("password", &"<redacted>")
            .field("changed", &self.changed)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Default, PartialEq, Clone)]
pub struct TrashedEntry {
    pub entry: VaultEntry,
    pub history: Vec<PasswordRevision>,
    pub deleted: String,
}

impl std::fmt::Debug for TrashedEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrashedEntry")
            .field("entry", &self.entry)
            .field("history", &self.history)
            .field("deleted", &self.deleted)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Default, PartialEq, Clone)]
pub struct TotpRecord {
    pub entry_id: usize,
    pub configuration: String,
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct EntryMetadata {
    pub entry_id: usize,
    pub kind: ItemKind,
    pub additional_urls: Vec<String>,
    pub password_changed: Option<String>,
    pub custom_fields: Vec<CustomField>,
}

struct MetadataUpdate<'a> {
    kind: Option<ItemKind>,
    add_urls: &'a [String],
    remove_urls: &'a [String],
    clear_urls: bool,
    primary_url: Option<&'a str>,
    password_changed: bool,
    set_fields: &'a [CustomField],
    remove_fields: &'a [String],
    clear_fields: bool,
}

impl std::fmt::Debug for TotpRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TotpRecord")
            .field("entry_id", &self.entry_id)
            .field("configuration", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct RecoveryData {
    pub password_history: Vec<PasswordRevision>,
    pub trash: Vec<TrashedEntry>,
    pub next_entry_id: usize,
    pub totp: Vec<TotpRecord>,
    pub entry_metadata: Vec<EntryMetadata>,
}

impl Zeroize for PasswordRevision {
    fn zeroize(&mut self) {
        self.entry_id.zeroize();
        self.password.zeroize();
        self.changed.zeroize();
        *self = Self::default();
    }
}

impl Zeroize for TrashedEntry {
    fn zeroize(&mut self) {
        self.entry.zeroize();
        self.history.zeroize();
        self.deleted.zeroize();
        *self = Self::default();
    }
}

impl Zeroize for TotpRecord {
    fn zeroize(&mut self) {
        self.entry_id.zeroize();
        self.configuration.zeroize();
        *self = Self::default();
    }
}

impl Zeroize for RecoveryData {
    fn zeroize(&mut self) {
        self.password_history.zeroize();
        self.trash.zeroize();
        self.next_entry_id.zeroize();
        self.totp.zeroize();
        self.entry_metadata.zeroize();
        *self = Self::default();
    }
}

impl Zeroize for EntryMetadata {
    fn zeroize(&mut self) {
        self.entry_id.zeroize();
        self.additional_urls.zeroize();
        self.password_changed.zeroize();
        self.custom_fields.zeroize();
        *self = Self::default();
    }
}
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct VaultMetadata {
    pub filename: String,
}
impl Zeroize for VaultMetadata {
    fn zeroize(&mut self) {
        self.filename.zeroize();
        *self = Self::default();
    }
}

#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct Vault {
    pub entries: Vec<VaultEntry>,
    pub metadata: VaultMetadata,
    pub recovery: RecoveryData,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub total: usize,
    pub added: usize,
    pub replaced: usize,
    pub skipped: usize,
    pub renamed: usize,
    pub preview: bool,
}

pub(crate) struct AuditSnapshot {
    entries: Vec<AuditEntrySnapshot>,
}

struct AuditEntrySnapshot {
    id: usize,
    name: String,
    username: Option<String>,
    password_hash: String,
    weak: bool,
    stale: bool,
    password_changed: String,
    missing_totp: bool,
    identity: (String, String),
}

impl Drop for AuditSnapshot {
    fn drop(&mut self) {
        for entry in &mut self.entries {
            entry.name.zeroize();
            entry.username.zeroize();
            entry.password_hash.zeroize();
            entry.password_changed.zeroize();
            entry.identity.0.zeroize();
            entry.identity.1.zeroize();
        }
    }
}

impl AuditSnapshot {
    fn report(
        &self,
        breached: Option<&HashMap<String, u64>>,
        breach_error: Option<&str>,
    ) -> String {
        let mut weak = Vec::new();
        let mut stale = Vec::new();
        let mut missing_totp = Vec::new();
        let mut breached_entries = Vec::new();
        let mut passwords: HashMap<&str, Vec<&AuditEntrySnapshot>> = HashMap::new();
        let mut identities: HashMap<&(String, String), Vec<&AuditEntrySnapshot>> = HashMap::new();
        let mut unhealthy = HashSet::new();

        for entry in &self.entries {
            if entry.weak {
                weak.push(entry);
                unhealthy.insert(entry.id);
            }
            if entry.stale {
                stale.push(entry);
                unhealthy.insert(entry.id);
            }
            if entry.missing_totp {
                missing_totp.push(entry);
                unhealthy.insert(entry.id);
            }
            if let Some(count) = breached
                .and_then(|hashes| hashes.get(&entry.password_hash))
                .copied()
            {
                breached_entries.push((entry, count));
                unhealthy.insert(entry.id);
            }
            passwords
                .entry(&entry.password_hash)
                .or_default()
                .push(entry);
            identities.entry(&entry.identity).or_default().push(entry);
        }
        let reused: Vec<_> = passwords
            .values()
            .filter(|entries| entries.len() > 1)
            .collect();
        for entries in &reused {
            unhealthy.extend(entries.iter().map(|entry| entry.id));
        }
        let duplicates: Vec<_> = identities
            .values()
            .filter(|entries| entries.len() > 1)
            .collect();
        for entries in &duplicates {
            unhealthy.extend(entries.iter().map(|entry| entry.id));
        }
        let healthy = self.entries.len().saturating_sub(unhealthy.len());
        let score = if self.entries.is_empty() {
            100
        } else {
            healthy * 100 / self.entries.len()
        };
        let mut report = format!(
            "Health score: {score}/100 ({healthy}/{} login entries have no detected issues).\nAudit: {} weak entries, {} reused-password groups, {} duplicate-login groups, {} stale entries, {} missing TOTP, {} breached entries.\n",
            self.entries.len(),
            weak.len(),
            reused.len(),
            duplicates.len(),
            stale.len(),
            missing_totp.len(),
            breached_entries.len(),
        );
        for entry in weak {
            report.push_str(&format!(
                "Weak: {}. {} {:?}\n",
                entry.id, entry.name, entry.username
            ));
        }
        for entries in reused {
            let labels = entries
                .iter()
                .map(|entry| format!("{}. {}", entry.id, entry.name))
                .collect::<Vec<_>>()
                .join(", ");
            report.push_str(&format!("Reused password: {labels}\n"));
        }
        for entries in duplicates {
            let labels = entries
                .iter()
                .map(|entry| format!("{}. {}", entry.id, entry.name))
                .collect::<Vec<_>>()
                .join(", ");
            report.push_str(&format!("Duplicate login: {labels}\n"));
        }
        for entry in stale {
            report.push_str(&format!(
                "Stale password: {}. {} (last changed {})\n",
                entry.id, entry.name, entry.password_changed
            ));
        }
        for entry in missing_totp {
            report.push_str(&format!("Missing TOTP: {}. {}\n", entry.id, entry.name));
        }
        for (entry, count) in breached_entries {
            report.push_str(&format!(
                "Breached password: {}. {} (seen {count} times)\n",
                entry.id, entry.name
            ));
        }
        if let Some(error) = breach_error {
            report.push_str(&format!("Breach check unavailable: {error}\n"));
        }
        report
    }

    pub(crate) async fn audit(&self, check_breaches: bool, stream: &mut TcpStream) {
        let breach_result = if check_breaches {
            Some(
                breached_hashes(
                    self.entries
                        .iter()
                        .map(|entry| entry.password_hash.as_str()),
                )
                .await,
            )
        } else {
            None
        };
        let (breached, error) = match breach_result.as_ref() {
            Some(Ok(matches)) => (Some(matches), None),
            Some(Err(error)) => (None, Some(error.as_str())),
            None => (None, None),
        };
        let code = if error.is_some() {
            ResponseCode::Failure
        } else {
            ResponseCode::Success
        };
        let report = self.report(breached, error);
        respond_with_code(code, &report, stream).await;
    }
}

const PORTABLE_FORMAT: &str = "password-manager-portable";
const PORTABLE_VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
struct PortableExport {
    format: String,
    version: u8,
    exported_at: String,
    items: Vec<PortableItem>,
}

#[derive(Serialize, Deserialize)]
struct PortableItem {
    id: usize,
    name: String,
    username: Option<String>,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    created: String,
    modified: String,
    #[serde(rename = "type")]
    kind: ItemKind,
    additional_urls: Vec<String>,
    custom_fields: Vec<CustomField>,
    password_changed: Option<String>,
    password_history: Vec<PortableRevision>,
    totp: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct PortableRevision {
    password: String,
    changed: String,
}

impl Zeroize for PortableRevision {
    fn zeroize(&mut self) {
        self.password.zeroize();
        self.changed.zeroize();
    }
}

impl Zeroize for PortableItem {
    fn zeroize(&mut self) {
        self.id.zeroize();
        self.name.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.notes.zeroize();
        self.created.zeroize();
        self.modified.zeroize();
        self.additional_urls.zeroize();
        self.custom_fields.zeroize();
        self.password_changed.zeroize();
        self.password_history.zeroize();
        self.totp.zeroize();
    }
}

impl Zeroize for PortableExport {
    fn zeroize(&mut self) {
        self.format.zeroize();
        self.version.zeroize();
        self.exported_at.zeroize();
        self.items.zeroize();
    }
}

struct ImportedItem {
    portable: bool,
    entry: VaultEntry,
    kind: ItemKind,
    additional_urls: Vec<String>,
    custom_fields: Vec<CustomField>,
    password_changed: Option<String>,
    password_history: Vec<PortableRevision>,
    totp: Option<String>,
}

impl Zeroize for ImportedItem {
    fn zeroize(&mut self) {
        self.portable.zeroize();
        self.entry.zeroize();
        self.additional_urls.zeroize();
        self.custom_fields.zeroize();
        self.password_changed.zeroize();
        self.password_history.zeroize();
        self.totp.zeroize();
    }
}

impl Drop for ImportedItem {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ImportedItem {
    fn login(entry: VaultEntry) -> Self {
        Self {
            portable: false,
            entry,
            kind: ItemKind::Login,
            additional_urls: Vec::new(),
            custom_fields: Vec::new(),
            password_changed: None,
            password_history: Vec::new(),
            totp: None,
        }
    }
}

impl std::fmt::Display for ImportReport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Import {}: {} parsed, {} added, {} replaced, {} kept with a new name, {} skipped.",
            if self.preview { "preview" } else { "finished" },
            self.total,
            self.added,
            self.replaced,
            self.renamed,
            self.skipped
        )
    }
}

const BACKUP_MAGIC: &[u8; 8] = b"PMBACKUP";
const BACKUP_VERSION: u8 = 1;
const MAX_BACKUP_BYTES: u64 = 128 * 1024 * 1024;
const MAX_VAULT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_IMPORT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_IMPORT_ITEMS: usize = 100_000;

fn run_blocking_io<T>(operation: impl FnOnce() -> T) -> T {
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|handle| handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        tokio::task::block_in_place(operation)
    } else {
        operation()
    }
}

#[derive(Serialize)]
struct BackupEnvelopeRef<'a> {
    version: u8,
    created: String,
    vault: &'a Vault,
}

#[derive(Deserialize)]
struct BackupEnvelope {
    version: u8,
    created: String,
    vault: Vault,
}

fn random_vault_filename() -> String {
    loop {
        let filename = format!("{}.enc", hex::encode(rand::random::<[u8; 16]>()));
        if !data_dir().join(&filename).exists() {
            return filename;
        }
    }
}

fn find_vault(key_pass: &mut PasswordType) -> Option<(String, Vault)> {
    let candidates = fs::read_dir(data_dir())
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let filename = entry.file_name().into_string().ok()?;
            filename.ends_with(".enc").then_some(filename)
        });

    for filename in candidates {
        let path = data_dir().join(&filename);
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.file_type().is_file() || metadata.len() > MAX_VAULT_BYTES {
            continue;
        }
        let Ok(contents) = read(path) else {
            continue;
        };
        let Some(mut decrypted) = decrypt_file(key_pass, &contents) else {
            continue;
        };
        let decoded = rmp_serde::from_slice::<Vault>(&decrypted);
        decrypted.zeroize();
        let Ok(mut vault) = decoded else {
            continue;
        };
        if vault.ensure_next_entry_id().is_err() {
            vault.zeroize();
            continue;
        }
        vault.metadata.filename = filename.clone();
        return Some((filename, vault));
    }
    None
}

pub fn create_vault(
    vlt: &mut Option<Vault>,
    server_info: &mut ServerInfo,
    lock: bool,
) -> Result<(), String> {
    if let Some(PasswordType::Password(password)) = server_info.keypass.as_ref()
        && let Err(error) = validate_new_password(password)
    {
        server_info.zeroize();
        return Err(error.to_string());
    }
    let generated_key_path = match server_info.keypass.as_ref() {
        Some(PasswordType::Key(path)) if !new_key_file_path(path)?.exists() => {
            Some(new_key_file_path(path)?)
        }
        _ => None,
    };
    if matches!(server_info.keypass, Some(PasswordType::Key(_))) {
        let mut key = try_gen_master_key(server_info.keypass.as_mut().unwrap(), true)?;
        key.zeroize();
    } else if let Some((_, mut existing)) = find_vault(server_info.keypass.as_mut().unwrap()) {
        existing.zeroize();
        server_info.zeroize();
        return Err("A vault file with this password already exists.".to_string());
    }
    let fname = random_vault_filename();
    let file_path = data_dir().join(&fname);
    if file_exists(&file_path) {
        if let Some(path) = generated_key_path {
            let _ = fs::remove_file(path);
        }
        return Err("A vault file with this key already exists.".to_string());
    }
    *vlt = Some(Vault {
        entries: Vec::new(),
        metadata: VaultMetadata {
            filename: fname.clone(),
        },
        recovery: RecoveryData::default(),
    });
    if let Err(error) = write_vault(
        vlt.as_ref().expect("vault was just initialized"),
        server_info,
    ) {
        vlt.zeroize();
        if let Some(path) = generated_key_path {
            let _ = fs::remove_file(path);
        }
        return Err(error);
    }
    if lock {
        vlt.zeroize();
        server_info.zeroize();
    }
    Ok(())
}
fn write_vault(vlt: &Vault, key_pass: &mut ServerInfo) -> Result<(), String> {
    if key_pass.keypass.is_none() {
        // This permits detached in-memory vault values used by callers and tests;
        // the running server never mutates a vault without an active key.
        return Ok(());
    }
    write_vault_with_key(vlt, key_pass.keypass.as_mut().unwrap())
}

fn write_vault_with_key(vlt: &Vault, key_pass: &mut PasswordType) -> Result<(), String> {
    let fname = vlt.metadata.filename.clone();
    let file_path = data_dir().join(&fname);
    let buf = run_blocking_io(|| rmp_serde::to_vec(&vlt))
        .map_err(|e| format!("could not encode vault: {e}"))?;
    let mut txt = try_encrypt_file_in_place(key_pass, buf)?;
    let result = run_blocking_io(|| {
        let mut temporary = NamedTempFile::new_in(data_dir())
            .map_err(|e| format!("could not create vault temp file: {e}"))?;
        set_private_perms(temporary.path())
            .map_err(|e| format!("could not protect vault temp file: {e}"))?;
        temporary
            .write_all(&txt)
            .map_err(|e| format!("could not write encrypted vault: {e}"))?;
        temporary
            .as_file()
            .sync_all()
            .map_err(|e| format!("could not sync encrypted vault: {e}"))?;
        temporary
            .persist(&file_path)
            .map_err(|e| format!("could not atomically replace vault file: {}", e.error))?;
        sync_parent(&file_path).map_err(|e| format!("could not sync vault directory: {e}"))?;
        Ok(())
    });
    txt.zeroize();
    result
}

fn persist_private_file(path: &Path, contents: &[u8], force: bool) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    run_blocking_io(|| {
        let mut temporary = NamedTempFile::new_in(parent)
            .map_err(|error| format!("could not create private temp file: {error}"))?;
        set_private_perms(temporary.path())
            .map_err(|error| format!("could not protect private temp file: {error}"))?;
        temporary
            .write_all(contents)
            .and_then(|_| temporary.as_file().sync_all())
            .map_err(|error| format!("could not write private file: {error}"))?;
        if force {
            temporary
                .persist(path)
                .map_err(|error| format!("could not replace private file: {}", error.error))?;
        } else {
            temporary.persist_noclobber(path).map_err(|error| {
                if error.error.kind() == std::io::ErrorKind::AlreadyExists {
                    format!(
                        "destination file {:?} already exists; use --force to replace it",
                        path
                    )
                } else {
                    format!("could not create private file: {}", error.error)
                }
            })?;
        }
        sync_parent(path)
            .map_err(|error| format!("could not sync private file directory: {error}"))?;
        Ok(())
    })
}

fn validate_backup_vault(vault: &mut Vault) -> Result<(), String> {
    let mut ids = HashSet::new();
    for id in vault
        .entries
        .iter()
        .map(|entry| entry.id)
        .chain(vault.recovery.trash.iter().map(|item| item.entry.id))
    {
        if id == 0 || !ids.insert(id) {
            return Err("backup contains invalid or duplicate entry IDs".to_string());
        }
    }
    if vault
        .recovery
        .password_history
        .iter()
        .any(|revision| !ids.contains(&revision.entry_id))
        || vault
            .recovery
            .totp
            .iter()
            .any(|record| !ids.contains(&record.entry_id))
        || vault
            .recovery
            .entry_metadata
            .iter()
            .any(|record| !ids.contains(&record.entry_id))
    {
        return Err("backup contains recovery records for unknown entries".to_string());
    }
    if vault.recovery.trash.iter().any(|item| {
        item.history
            .iter()
            .any(|revision| revision.entry_id != item.entry.id)
    }) {
        return Err("backup contains mismatched trash history".to_string());
    }
    let mut totp_ids = HashSet::new();
    if vault
        .recovery
        .totp
        .iter()
        .any(|record| !totp_ids.insert(record.entry_id))
    {
        return Err("backup contains duplicate TOTP records".to_string());
    }
    let mut metadata_ids = HashSet::new();
    if vault
        .recovery
        .entry_metadata
        .iter()
        .any(|record| !metadata_ids.insert(record.entry_id))
    {
        return Err("backup contains duplicate item metadata records".to_string());
    }
    vault.ensure_next_entry_id()
}

pub fn restore_encrypted_backup(
    path: &str,
    key_pass: &mut PasswordType,
    force: bool,
) -> Result<String, String> {
    let mut vault_lookup_key = Zeroizing::new(key_pass.clone());
    let metadata = fs::metadata(path)
        .map_err(|error| format!("could not open backup file {path:?}: {error}"))?;
    if metadata.len() > MAX_BACKUP_BYTES {
        return Err("backup file exceeds the 128 MiB limit".to_string());
    }
    let mut contents =
        fs::read(path).map_err(|error| format!("could not read backup file {path:?}: {error}"))?;
    if contents.len() < BACKUP_MAGIC.len() + 1
        || &contents[..BACKUP_MAGIC.len()] != BACKUP_MAGIC
        || contents[BACKUP_MAGIC.len()] != BACKUP_VERSION
    {
        contents.zeroize();
        return Err("unsupported or invalid encrypted backup format".to_string());
    }
    let mut plaintext = match decrypt_file(key_pass, &contents[BACKUP_MAGIC.len() + 1..]) {
        Some(plaintext) => plaintext,
        None => {
            contents.zeroize();
            return Err("wrong backup password/key, or corrupted backup".to_string());
        }
    };
    contents.zeroize();
    let decoded = rmp_serde::from_slice::<BackupEnvelope>(&plaintext)
        .map_err(|error| format!("could not decode backup: {error}"));
    plaintext.zeroize();
    let mut backup = decoded?;
    if backup.version != BACKUP_VERSION {
        backup.vault.zeroize();
        backup.created.zeroize();
        return Err("unsupported encrypted backup version".to_string());
    }
    let result = (|| {
        validate_backup_vault(&mut backup.vault)?;
        let existing = find_vault(&mut vault_lookup_key).map(|(filename, mut vault)| {
            vault.zeroize();
            filename
        });
        if existing.is_some() && !force {
            return Err(
                "a vault already exists for this backup password/key; use --force to replace it"
                    .to_string(),
            );
        }
        let filename = existing.unwrap_or_else(random_vault_filename);
        backup.vault.metadata.filename = filename.clone();
        write_vault_with_key(&backup.vault, key_pass)?;
        Ok(filename)
    })();
    backup.vault.zeroize();
    backup.created.zeroize();
    result
}

fn unlock_vault(key_pass: &mut ServerInfo) -> Option<Vault> {
    let kp = key_pass.keypass.as_mut()?;
    if let PasswordType::Key(key) = kp
        && !key_file_path(key).ok()?.is_file()
    {
        return None;
    }
    let (_, vault) = find_vault(key_pass.keypass.as_mut().unwrap())?;
    key_pass.locked = false;
    Some(vault)
}

fn url_match_json(
    entries: &[VaultEntry],
    totp_records: &[TotpRecord],
    metadata: &[EntryMetadata],
    url: &str,
) -> Option<String> {
    let metadata_by_id: HashMap<_, _> = metadata
        .iter()
        .map(|record| (record.entry_id, record))
        .collect();
    let totp_ids: HashSet<_> = totp_records.iter().map(|record| record.entry_id).collect();
    let mut results = Vec::new();
    for e in entries {
        let item_metadata = metadata_by_id.get(&e.id).copied();
        if item_metadata.is_some_and(|record| record.kind != ItemKind::Login) {
            continue;
        }
        let matches = e
            .url
            .as_deref()
            .is_some_and(|saved| hosts_match(saved, url))
            || item_metadata.is_some_and(|record| {
                record
                    .additional_urls
                    .iter()
                    .any(|saved| hosts_match(saved, url))
            });
        if matches {
            results.push(json!({
                "id": e.id,
                "username": e.username.clone().unwrap_or_else(|| "None".to_string()),
                "password": e.password,
                "name": e.name,
                "has_totp": totp_ids.contains(&e.id),
            }));
        }
    }
    if results.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&results).unwrap())
    }
}

fn hostname(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let authority = value
        .split_once("://")
        .map_or(value, |(_, remainder)| remainder)
        .split(['/', '?', '#'])
        .next()?;
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = if host_port.starts_with('[') {
        host_port
            .split_once(']')
            .map_or(host_port, |(host, _)| host)
    } else {
        host_port
            .split_once(':')
            .map_or(host_port, |(host, _)| host)
    };
    let host = host.trim_matches(['[', ']']).trim_end_matches('.');
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn url_scheme(value: &str) -> Option<&str> {
    let (scheme, _) = value.trim().split_once("://")?;
    (scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https")).then_some(scheme)
}

fn hosts_match(saved_url: &str, requested_url: &str) -> bool {
    let (Some(saved), Some(requested)) = (hostname(saved_url), hostname(requested_url)) else {
        return false;
    };
    if url_scheme(requested_url).is_some_and(|scheme| scheme.eq_ignore_ascii_case("http"))
        && !url_scheme(saved_url).is_some_and(|scheme| scheme.eq_ignore_ascii_case("http"))
    {
        return false;
    }
    if let Some(base) = saved.strip_prefix("*.") {
        // Wildcards must be rooted at a registrable domain, never a public
        // suffix such as "com", "co.uk", or "github.io".
        return psl::domain_str(base) == Some(base)
            && requested != base
            && requested.ends_with(&format!(".{base}"));
    }
    saved == requested
}

fn is_otpauth_uri(value: &str) -> bool {
    value
        .get(.."otpauth://".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("otpauth://"))
}

const MIN_COMPATIBLE_TOTP_SECRET_BYTES: usize = 10;

fn compatible_totp_from_url(value: &str) -> Result<Totp, String> {
    match Totp::from_url(value) {
        Ok(totp) => Ok(totp),
        Err(TotpError::SecretTooShort { bits }) if bits >= MIN_COMPATIBLE_TOTP_SECRET_BYTES * 8 => {
            let totp = Totp::from_url_unchecked(value)
                .map_err(|error| format!("invalid otpauth URI: {error}"))?;
            if !(6..=8).contains(&totp.digits()) {
                return Err(format!(
                    "invalid otpauth URI: unsupported digit count {}",
                    totp.digits()
                ));
            }
            if totp.step() == 0 {
                return Err("invalid otpauth URI: period cannot be zero".to_string());
            }
            Ok(totp)
        }
        Err(error) => Err(format!("invalid otpauth URI: {error}")),
    }
}

fn compatible_totp_from_secret(secret: TotpSecret) -> Result<Totp, String> {
    let secret_bytes = secret.as_ref().len();
    if secret_bytes < MIN_COMPATIBLE_TOTP_SECRET_BYTES {
        return Err(format!(
            "TOTP secret must be at least {} bits, got {} bits",
            MIN_COMPATIBLE_TOTP_SECRET_BYTES * 8,
            secret_bytes * 8
        ));
    }
    let builder = TotpBuilder::new().with_secret(secret);
    if secret_bytes < 16 {
        Ok(builder.build_noncompliant())
    } else {
        builder
            .build()
            .map_err(|error| format!("invalid TOTP configuration: {error}"))
    }
}

fn normalize_totp_configuration(value: &str) -> Result<(String, usize), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("TOTP configuration cannot be empty".to_string());
    }
    if trimmed.len() > 4096 {
        return Err("TOTP configuration is too long".to_string());
    }
    if is_otpauth_uri(trimmed) {
        let totp = compatible_totp_from_url(trimmed)?;
        return Ok((trimmed.to_string(), totp.secret().as_ref().len() * 8));
    }

    let mut normalized: String = trimmed
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '-')
        .flat_map(char::to_uppercase)
        .collect();
    let secret = match TotpSecret::try_from_base32(&normalized) {
        Ok(secret) => secret,
        Err(error) => {
            normalized.zeroize();
            return Err(format!("invalid Base32 TOTP secret: {error}"));
        }
    };
    let secret_bits = secret.as_ref().len() * 8;
    if let Err(error) = compatible_totp_from_secret(secret) {
        normalized.zeroize();
        return Err(error);
    }
    Ok((normalized, secret_bits))
}

fn parse_totp_configuration(value: &str) -> Result<Totp, String> {
    if is_otpauth_uri(value) {
        compatible_totp_from_url(value)
    } else {
        let secret = TotpSecret::try_from_base32(value)
            .map_err(|error| format!("invalid Base32 TOTP secret: {error}"))?;
        compatible_totp_from_secret(secret)
    }
}

impl Vault {
    fn ensure_next_entry_id(&mut self) -> Result<(), String> {
        let highest_id = self
            .entries
            .iter()
            .map(|entry| entry.id)
            .chain(self.recovery.trash.iter().map(|trashed| trashed.entry.id))
            .max()
            .unwrap_or(0);
        if self.recovery.next_entry_id <= highest_id {
            self.recovery.next_entry_id = highest_id
                .checked_add(1)
                .ok_or_else(|| "entry ID space is exhausted".to_string())?;
        }
        if self.recovery.next_entry_id == 0 {
            self.recovery.next_entry_id = 1;
        }
        Ok(())
    }

    fn allocate_entry_id(&mut self) -> Result<usize, String> {
        self.ensure_next_entry_id()?;
        let id = self.recovery.next_entry_id;
        self.recovery.next_entry_id = id
            .checked_add(1)
            .ok_or_else(|| "entry ID space is exhausted".to_string())?;
        Ok(id)
    }

    fn entry_index(&self, target: &Target) -> Option<usize> {
        match target {
            Target::Id(id) => self.entries.iter().position(|entry| entry.id == *id),
            Target::Name(name) => self.entries.iter().position(|entry| entry.name == *name),
            Target::Url(_) | Target::Vault { .. } => None,
        }
    }

    fn push_password_history_with_limit(
        &mut self,
        entry_id: usize,
        mut password: String,
        limit: usize,
    ) {
        if limit == 0 {
            password.zeroize();
            return;
        }
        self.recovery.password_history.push(PasswordRevision {
            entry_id,
            password,
            changed: chrono::Local::now().to_string(),
        });
        let mut count = self
            .recovery
            .password_history
            .iter()
            .filter(|revision| revision.entry_id == entry_id)
            .count();
        while count > limit {
            let Some(index) = self
                .recovery
                .password_history
                .iter()
                .position(|revision| revision.entry_id == entry_id)
            else {
                break;
            };
            let mut removed = self.recovery.password_history.remove(index);
            removed.zeroize();
            count -= 1;
        }
    }

    fn metadata(&self, entry_id: usize) -> Option<&EntryMetadata> {
        self.recovery
            .entry_metadata
            .iter()
            .find(|record| record.entry_id == entry_id)
    }

    fn metadata_snapshot(&self, entry_id: usize) -> Option<(usize, EntryMetadata)> {
        self.recovery
            .entry_metadata
            .iter()
            .enumerate()
            .find(|(_, record)| record.entry_id == entry_id)
            .map(|(index, record)| (index, record.clone()))
    }

    fn restore_metadata_snapshot(
        &mut self,
        entry_id: usize,
        snapshot: Option<(usize, EntryMetadata)>,
    ) {
        if let Some(index) = self
            .recovery
            .entry_metadata
            .iter()
            .position(|record| record.entry_id == entry_id)
        {
            let mut current = self.recovery.entry_metadata.remove(index);
            current.zeroize();
        }
        if let Some((index, metadata)) = snapshot {
            self.recovery
                .entry_metadata
                .insert(index.min(self.recovery.entry_metadata.len()), metadata);
        }
    }

    fn history_snapshot(&self, entry_id: usize) -> Vec<(usize, PasswordRevision)> {
        self.recovery
            .password_history
            .iter()
            .enumerate()
            .filter(|(_, revision)| revision.entry_id == entry_id)
            .map(|(index, revision)| (index, revision.clone()))
            .collect()
    }

    fn restore_history_snapshot(
        &mut self,
        entry_id: usize,
        snapshot: Vec<(usize, PasswordRevision)>,
    ) {
        let mut retained = Vec::with_capacity(self.recovery.password_history.len());
        for mut revision in std::mem::take(&mut self.recovery.password_history) {
            if revision.entry_id == entry_id {
                revision.zeroize();
            } else {
                retained.push(revision);
            }
        }
        self.recovery.password_history = retained;
        for (index, revision) in snapshot {
            self.recovery
                .password_history
                .insert(index.min(self.recovery.password_history.len()), revision);
        }
    }

    fn item_kind(&self, entry_id: usize) -> ItemKind {
        self.metadata(entry_id)
            .map_or(ItemKind::Login, |record| record.kind)
    }

    fn all_urls<'a>(&'a self, entry: &'a VaultEntry) -> impl Iterator<Item = &'a str> {
        entry.url.as_deref().into_iter().chain(
            self.metadata(entry.id)
                .into_iter()
                .flat_map(|record| record.additional_urls.iter().map(String::as_str)),
        )
    }

    fn password_changed<'a>(&'a self, entry: &'a VaultEntry) -> &'a str {
        self.metadata(entry.id)
            .and_then(|record| record.password_changed.as_deref())
            .unwrap_or(&entry.created)
    }

    fn password_is_stale(&self, entry: &VaultEntry, days: u64) -> bool {
        let changed = self.password_changed(entry);
        let parsed = chrono::DateTime::parse_from_rfc3339(changed)
            .or_else(|_| chrono::DateTime::parse_from_str(changed, "%Y-%m-%d %H:%M:%S%.f %:z"));
        let Ok(changed) = parsed else {
            return false;
        };
        chrono::Utc::now().signed_duration_since(changed.with_timezone(&chrono::Utc))
            >= chrono::Duration::days(i64::try_from(days).unwrap_or(i64::MAX))
    }

    fn custom_fields(&self, entry_id: usize) -> &[CustomField] {
        self.metadata(entry_id)
            .map_or(&[], |record| record.custom_fields.as_slice())
    }

    fn entry_details(&self, entry: &VaultEntry) -> String {
        let fields = self
            .custom_fields(entry.id)
            .iter()
            .map(|field| format!("{}={}", field.name, field.value))
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "Type: {}\nURLs: {:?}\n{:?}{}{}\n",
            self.item_kind(entry.id),
            self.all_urls(entry).collect::<Vec<_>>(),
            entry,
            if fields.is_empty() {
                ""
            } else {
                "\nCustom fields:\n"
            },
            fields
        )
    }

    fn apply_metadata_update(&mut self, entry_id: usize, update: MetadataUpdate<'_>) -> bool {
        let requested = update.kind.is_some()
            || !update.add_urls.is_empty()
            || !update.remove_urls.is_empty()
            || update.clear_urls
            || update.password_changed
            || !update.set_fields.is_empty()
            || !update.remove_fields.is_empty()
            || update.clear_fields;
        if !requested {
            return false;
        }
        let index = if let Some(index) = self
            .recovery
            .entry_metadata
            .iter()
            .position(|record| record.entry_id == entry_id)
        {
            index
        } else {
            self.recovery.entry_metadata.push(EntryMetadata {
                entry_id,
                ..EntryMetadata::default()
            });
            self.recovery.entry_metadata.len() - 1
        };
        let record = &mut self.recovery.entry_metadata[index];
        let before = record.clone();
        if let Some(kind) = update.kind {
            record.kind = kind;
        }
        if update.clear_urls {
            record.additional_urls.clear();
        }
        record
            .additional_urls
            .retain(|url| !update.remove_urls.iter().any(|removed| removed == url));
        if let Some(primary) = update.primary_url {
            record.additional_urls.retain(|url| url != primary);
        }
        for url in update.add_urls {
            let url = url.trim();
            if !url.is_empty() && !record.additional_urls.iter().any(|saved| saved == url) {
                record.additional_urls.push(url.to_string());
            }
        }
        if update.password_changed {
            record.password_changed = Some(chrono::Local::now().to_string());
        }
        if update.clear_fields {
            record.custom_fields.zeroize();
            record.custom_fields.clear();
        }
        for name in update.remove_fields {
            let name = name.trim();
            let mut retained = Vec::with_capacity(record.custom_fields.len());
            for mut field in std::mem::take(&mut record.custom_fields) {
                if field.name.eq_ignore_ascii_case(name) {
                    field.zeroize();
                } else {
                    retained.push(field);
                }
            }
            record.custom_fields = retained;
        }
        for field in update.set_fields {
            if let Some(existing) = record
                .custom_fields
                .iter_mut()
                .find(|existing| existing.name.eq_ignore_ascii_case(&field.name))
            {
                existing.zeroize();
                *existing = field.clone();
            } else {
                record.custom_fields.push(field.clone());
            }
        }
        *record != before
    }

    pub fn rekey(
        &mut self,
        server_info: &mut ServerInfo,
        mut new_key: PasswordType,
    ) -> Result<(), String> {
        if let PasswordType::Password(password) = &new_key
            && let Err(error) = validate_new_password(password)
        {
            new_key.zeroize();
            return Err(error.to_string());
        }
        if let PasswordType::Key(path) = &new_key
            && new_key_file_path(path)?.exists()
        {
            return Err("the new key file already exists".to_string());
        }
        let old_filename = self.metadata.filename.clone();
        if matches!(&new_key, PasswordType::Key(_)) {
            let mut key = try_gen_master_key(&mut new_key, true)?;
            key.zeroize();
        } else if let Some((_, mut existing)) = find_vault(&mut new_key) {
            existing.zeroize();
            new_key.zeroize();
            return Err("a vault already exists for the new password".to_string());
        }
        let new_filename = random_vault_filename();
        let new_path = data_dir().join(&new_filename);
        if new_path.exists() {
            if let PasswordType::Key(path) = &new_key {
                let _ = fs::remove_file(new_key_file_path(path)?);
            }
            return Err("a vault already exists for the new password or key".to_string());
        }

        self.metadata.filename = new_filename.clone();
        let mut replacement = ServerInfo {
            locked: false,
            keypass: Some(new_key.clone()),
        };
        if let Err(error) = write_vault(self, &mut replacement) {
            replacement.zeroize();
            self.metadata.filename = old_filename;
            if let PasswordType::Key(path) = &new_key {
                let _ = fs::remove_file(new_key_file_path(path)?);
            }
            return Err(error);
        }
        if let Err(error) = fs::remove_file(data_dir().join(&old_filename)) {
            replacement.zeroize();
            let _ = fs::remove_file(&new_path);
            if let PasswordType::Key(path) = &new_key {
                let _ = fs::remove_file(new_key_file_path(path)?);
            }
            self.metadata.filename = old_filename;
            return Err(format!("could not replace the old vault: {error}"));
        }
        let cached_new_key = replacement.keypass.take().unwrap_or(new_key);
        replacement.zeroize();
        if let Some(mut old_key) = server_info.keypass.replace(cached_new_key) {
            old_key.zeroize();
        }
        Ok(())
    }

    pub async fn get_entry(&self, a: Target, stream: &mut TcpStream) {
        self.get_entry_with_timeout(a, 15, stream).await;
    }

    pub async fn get_entry_with_timeout(
        &self,
        a: Target,
        copy_timeout: u8,
        stream: &mut TcpStream,
    ) {
        match a {
            Target::Id(i) => {
                let Some(entry) = self.entries.iter().find(|entry| entry.id == i) else {
                    respond_with_code(ResponseCode::NotFound, "Invalid id.", stream).await;
                    return;
                };
                respond(&self.entry_details(entry), stream).await;
                if !entry.password.is_empty() {
                    copy_in_background(entry.password.clone(), copy_timeout);
                }
            }
            Target::Name(name) => {
                if let Some(entry) = self.entries.iter().find(|entry| entry.name == name) {
                    respond(&self.entry_details(entry), stream).await;
                    if !entry.password.is_empty() {
                        copy_in_background(entry.password.clone(), copy_timeout);
                    }
                } else {
                    respond_with_code(ResponseCode::NotFound, "Not found.\n", stream).await;
                }
            }
            Target::Url(u) => {
                if let Some(json) = url_match_json(
                    &self.entries,
                    &self.recovery.totp,
                    &self.recovery.entry_metadata,
                    &u,
                ) {
                    respond(&json, stream).await;
                } else {
                    respond_with_code(ResponseCode::NotFound, "Not found.\n", stream).await;
                }
            }
            Target::Vault { .. } => {
                respond_with_code(
                    ResponseCode::InvalidInput,
                    "Invalid entry selector.",
                    stream,
                )
                .await
            }
        }
    }

    pub async fn get_secret(&self, target: Target, stream: &mut TcpStream) {
        let entry = match target {
            Target::Id(id) => self.entries.iter().find(|entry| entry.id == id),
            Target::Name(name) => self.entries.iter().find(|entry| entry.name == name),
            Target::Url(_) | Target::Vault { .. } => None,
        };
        if let Some(entry) = entry {
            respond(&entry.password, stream).await;
        } else {
            respond_with_code(ResponseCode::NotFound, "Not found.\n", stream).await;
        }
    }

    pub fn add_entry(
        &mut self,
        info: PasswordEntry,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        self.add_typed_entry(
            TypedEntry {
                entry: info,
                kind: ItemKind::Login,
                additional_urls: Vec::new(),
                custom_fields: Vec::new(),
            },
            key_pass,
        )
    }

    pub fn add_typed_entry(
        &mut self,
        request: TypedEntry,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        let TypedEntry {
            entry: mut info,
            kind,
            additional_urls,
            custom_fields,
        } = request;
        info.url = info
            .url
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty());
        let mut normalized_urls = Vec::new();
        for url in additional_urls {
            let url = url.trim();
            if !url.is_empty()
                && info.url.as_deref() != Some(url)
                && !normalized_urls.iter().any(|saved| saved == url)
            {
                normalized_urls.push(url.to_string());
            }
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.name == info.name && entry.username == info.username)
        {
            return Ok(false);
        }

        let next_entry_id_before = self.recovery.next_entry_id;
        let id = self.allocate_entry_id()?;
        let now = chrono::Local::now().to_string();
        let password_changed = (!info.password.is_empty()).then(|| now.clone());
        self.entries.push(VaultEntry {
            id,
            name: info.name,
            username: info.username,
            password: info.password,
            url: info.url,
            notes: info.notes,
            created: now.clone(),
            modified: now,
        });
        let metadata_added =
            kind != ItemKind::Login || !normalized_urls.is_empty() || !custom_fields.is_empty();
        if metadata_added {
            self.recovery.entry_metadata.push(EntryMetadata {
                entry_id: id,
                kind,
                additional_urls: normalized_urls,
                password_changed,
                custom_fields,
            });
        }
        if let Err(error) = write_vault(self, key_pass) {
            self.entries.pop();
            if metadata_added {
                self.recovery.entry_metadata.pop().zeroize();
            }
            self.recovery.next_entry_id = next_entry_id_before;
            return Err(error);
        }
        Ok(true)
    }

    pub fn delete_entry(
        &mut self,
        target: Target,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        let index = self.entry_index(&target);
        let Some(index) = index else {
            return Ok(false);
        };

        let mut removed = self.entries.remove(index);
        let removed_id = removed.id;
        let history_snapshot = self.history_snapshot(removed_id);
        let mut history = Vec::with_capacity(history_snapshot.len());
        for (history_index, _) in history_snapshot.iter().rev() {
            history.push(self.recovery.password_history.remove(*history_index));
        }
        history.reverse();
        self.recovery.trash.push(TrashedEntry {
            entry: removed,
            history,
            deleted: chrono::Local::now().to_string(),
        });
        if let Err(error) = write_vault(self, key_pass) {
            let mut trashed = self
                .recovery
                .trash
                .pop()
                .expect("trash record was just added");
            removed = std::mem::take(&mut trashed.entry);
            trashed.zeroize();
            self.entries.insert(index, removed);
            self.restore_history_snapshot(removed_id, history_snapshot);
            return Err(error);
        }
        for (_, mut revision) in history_snapshot {
            revision.zeroize();
        }
        Ok(true)
    }

    pub fn update_entry_with_limit(
        &mut self,
        change: EntryUpdate,
        key_pass: &mut ServerInfo,
        password_history_limit: usize,
    ) -> Result<bool, String> {
        self.update_typed_entry_with_limit(
            TypedUpdate {
                entry: change,
                kind: None,
                add_url: Vec::new(),
                remove_url: Vec::new(),
                clear_urls: false,
                set_fields: Vec::new(),
                remove_fields: Vec::new(),
                clear_fields: false,
            },
            key_pass,
            password_history_limit,
        )
    }

    pub fn update_typed_entry_with_limit(
        &mut self,
        change: TypedUpdate,
        key_pass: &mut ServerInfo,
        password_history_limit: usize,
    ) -> Result<bool, String> {
        let TypedUpdate {
            entry: change,
            kind,
            add_url,
            remove_url,
            clear_urls,
            set_fields,
            remove_fields,
            clear_fields,
        } = change;
        let EntryUpdate {
            target,
            update,
            password,
        } = change;
        let index = self.entry_index(&target);
        let Some(index) = index else {
            return Ok(false);
        };

        let mut original = self.entries[index].clone();
        let metadata_before = self.metadata_snapshot(original.id);
        let history_before = self.history_snapshot(original.id);
        let password_changed = update.password
            && password
                .as_ref()
                .is_some_and(|new_password| *new_password != original.password);
        let old_password = password_changed.then(|| original.password.clone());
        let metadata_modified = self.apply_metadata_update(
            original.id,
            MetadataUpdate {
                kind,
                add_urls: &add_url,
                remove_urls: &remove_url,
                clear_urls,
                primary_url: update.url.as_deref(),
                password_changed,
                set_fields: &set_fields,
                remove_fields: &remove_fields,
                clear_fields,
            },
        );
        let mut modified = apply_update(&mut self.entries[index], update, password);
        if clear_urls {
            modified |= self.entries[index].url.take().is_some();
        } else if self.entries[index]
            .url
            .as_ref()
            .is_some_and(|url| remove_url.iter().any(|removed| removed == url))
        {
            self.entries[index].url = None;
            modified = true;
        }
        if modified || metadata_modified {
            self.entries[index].modified = chrono::Local::now().to_string();
        }
        if let Some(old_password) = old_password {
            self.push_password_history_with_limit(
                original.id,
                old_password,
                password_history_limit,
            );
        }
        if (modified || metadata_modified)
            && let Err(error) = write_vault(self, key_pass)
        {
            self.entries[index] = original;
            self.restore_metadata_snapshot(self.entries[index].id, metadata_before);
            self.restore_history_snapshot(self.entries[index].id, history_before);
            return Err(error);
        }
        original.zeroize();
        if let Some((_, mut metadata)) = metadata_before {
            metadata.zeroize();
        }
        for (_, mut revision) in history_before {
            revision.zeroize();
        }
        Ok(modified || metadata_modified)
    }

    pub fn set_totp(
        &mut self,
        target: Target,
        configuration: &str,
        key_pass: &mut ServerInfo,
    ) -> Result<Option<usize>, String> {
        let Some(entry_index) = self.entry_index(&target) else {
            return Ok(None);
        };
        let (normalized, secret_bits) = normalize_totp_configuration(configuration)?;
        let entry_id = self.entries[entry_index].id;
        let mut modified_before = self.entries[entry_index].modified.clone();
        let record_before = self
            .recovery
            .totp
            .iter()
            .enumerate()
            .find(|(_, record)| record.entry_id == entry_id)
            .map(|(index, record)| (index, record.clone()));

        if let Some(record) = self
            .recovery
            .totp
            .iter_mut()
            .find(|record| record.entry_id == entry_id)
        {
            record.configuration.zeroize();
            record.configuration = normalized;
        } else {
            self.recovery.totp.push(TotpRecord {
                entry_id,
                configuration: normalized,
            });
        }
        self.entries[entry_index].modified = chrono::Local::now().to_string();

        if let Err(error) = write_vault(self, key_pass) {
            self.entries[entry_index].modified.zeroize();
            self.entries[entry_index].modified = modified_before;
            if let Some(index) = self
                .recovery
                .totp
                .iter()
                .position(|record| record.entry_id == entry_id)
            {
                let mut current = self.recovery.totp.remove(index);
                current.zeroize();
            }
            if let Some((index, record)) = record_before {
                self.recovery
                    .totp
                    .insert(index.min(self.recovery.totp.len()), record);
            }
            return Err(error);
        }
        modified_before.zeroize();
        if let Some((_, mut record)) = record_before {
            record.zeroize();
        }
        Ok(Some(secret_bits))
    }

    pub fn remove_totp(
        &mut self,
        target: Target,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        let Some(entry_index) = self.entry_index(&target) else {
            return Ok(false);
        };
        let entry_id = self.entries[entry_index].id;
        let Some(record_index) = self
            .recovery
            .totp
            .iter()
            .position(|record| record.entry_id == entry_id)
        else {
            return Ok(false);
        };
        let mut modified_before = self.entries[entry_index].modified.clone();
        let mut removed = self.recovery.totp.remove(record_index);
        self.entries[entry_index].modified = chrono::Local::now().to_string();

        if let Err(error) = write_vault(self, key_pass) {
            self.entries[entry_index].modified.zeroize();
            self.entries[entry_index].modified = modified_before;
            self.recovery.totp.insert(record_index, removed);
            return Err(error);
        }
        removed.zeroize();
        modified_before.zeroize();
        Ok(true)
    }

    fn totp_at(&self, target: &Target, timestamp: u64) -> Result<(String, u64), String> {
        let Some(entry_index) = self.entry_index(target) else {
            return Err("entry not found".to_string());
        };
        let entry_id = self.entries[entry_index].id;
        let record = self
            .recovery
            .totp
            .iter()
            .find(|record| record.entry_id == entry_id)
            .ok_or_else(|| "entry has no TOTP authenticator".to_string())?;
        let totp = parse_totp_configuration(&record.configuration)?;
        let ttl = totp.step() - (timestamp % totp.step());
        Ok((totp.generate(timestamp).to_string(), ttl))
    }

    pub fn current_totp(&self, target: Target) -> Result<(String, u64), String> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "system clock is before the Unix epoch".to_string())?
            .as_secs();
        self.totp_at(&target, timestamp)
    }

    pub async fn view_password_history(&self, target: Target, stream: &mut TcpStream) {
        let Some(index) = self.entry_index(&target) else {
            respond_with_code(ResponseCode::NotFound, "Entry not found.", stream).await;
            return;
        };
        let entry = &self.entries[index];
        let revisions: Vec<_> = self
            .recovery
            .password_history
            .iter()
            .filter(|revision| revision.entry_id == entry.id)
            .rev()
            .collect();
        if revisions.is_empty() {
            respond("No password history.", stream).await;
            return;
        }
        for (index, revision) in revisions.iter().enumerate() {
            respond(
                &format!("{}. changed {}\n", index + 1, revision.changed),
                stream,
            )
            .await;
        }
    }

    pub fn restore_password(
        &mut self,
        target: Target,
        revision: usize,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        let Some(entry_index) = self.entry_index(&target) else {
            return Ok(false);
        };
        let entry_id = self.entries[entry_index].id;
        let history_indices: Vec<_> = self
            .recovery
            .password_history
            .iter()
            .enumerate()
            .filter_map(|(index, item)| (item.entry_id == entry_id).then_some(index))
            .collect();
        let Some(history_index) = revision
            .checked_sub(1)
            .and_then(|offset| history_indices.iter().rev().nth(offset))
            .copied()
        else {
            return Err("invalid password-history revision".to_string());
        };
        let mut entry_before = self.entries[entry_index].clone();
        let history_before = self.history_snapshot(entry_id);
        let metadata_before = self.metadata_snapshot(entry_id);
        let mut selected = self.recovery.password_history.remove(history_index);
        let current = std::mem::replace(&mut self.entries[entry_index].password, selected.password);
        selected.password = current;
        selected.changed = chrono::Local::now().to_string();
        self.recovery.password_history.push(selected);
        self.entries[entry_index].modified = chrono::Local::now().to_string();
        self.apply_metadata_update(
            entry_id,
            MetadataUpdate {
                kind: None,
                add_urls: &[],
                remove_urls: &[],
                clear_urls: false,
                primary_url: None,
                password_changed: true,
                set_fields: &[],
                remove_fields: &[],
                clear_fields: false,
            },
        );
        if let Err(error) = write_vault(self, key_pass) {
            self.entries[entry_index].zeroize();
            self.entries[entry_index] = entry_before;
            self.restore_history_snapshot(entry_id, history_before);
            self.restore_metadata_snapshot(entry_id, metadata_before);
            return Err(error);
        }
        entry_before.zeroize();
        for (_, mut revision) in history_before {
            revision.zeroize();
        }
        if let Some((_, mut metadata)) = metadata_before {
            metadata.zeroize();
        }
        Ok(true)
    }

    pub async fn view_trash(&self, stream: &mut TcpStream) {
        if self.recovery.trash.is_empty() {
            respond("Trash is empty.", stream).await;
            return;
        }
        for (index, item) in self.recovery.trash.iter().enumerate() {
            let totp = self.totp_marker(item.entry.id);
            respond(
                &format!(
                    "{}. {} [{}] {:?} deleted {}{}\n",
                    index + 1,
                    item.entry.name,
                    self.item_kind(item.entry.id),
                    item.entry.username,
                    item.deleted,
                    totp
                ),
                stream,
            )
            .await;
        }
    }

    pub fn restore_trashed(
        &mut self,
        trash_id: usize,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        let Some(index) = trash_id
            .checked_sub(1)
            .filter(|index| *index < self.recovery.trash.len())
        else {
            return Ok(false);
        };
        let mut trashed = self.recovery.trash.remove(index);
        if self.entries.iter().any(|entry| {
            entry.name == trashed.entry.name && entry.username == trashed.entry.username
        }) {
            self.recovery.trash.insert(index, trashed);
            return Err(
                "an active entry with the same name and username already exists".to_string(),
            );
        }
        let restored_id = trashed.entry.id;
        if self.entries.iter().any(|entry| entry.id == restored_id) {
            self.recovery.trash.insert(index, trashed);
            return Err("an active entry already uses this stable ID".to_string());
        }
        for revision in &mut trashed.history {
            revision.entry_id = restored_id;
        }
        let restored_history_len = trashed.history.len();
        self.recovery.password_history.append(&mut trashed.history);
        self.entries.push(std::mem::take(&mut trashed.entry));
        if let Err(error) = write_vault(self, key_pass) {
            trashed.entry = self.entries.pop().expect("entry was just restored");
            trashed.history = self
                .recovery
                .password_history
                .split_off(self.recovery.password_history.len() - restored_history_len);
            self.recovery.trash.insert(index, trashed);
            return Err(error);
        }
        trashed.zeroize();
        Ok(true)
    }

    pub fn purge_trash(
        &mut self,
        trash_id: Option<usize>,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        let indexes = if let Some(id) = trash_id {
            let Some(index) = id
                .checked_sub(1)
                .filter(|index| *index < self.recovery.trash.len())
            else {
                return Ok(false);
            };
            vec![index]
        } else {
            if self.recovery.trash.is_empty() {
                return Ok(false);
            }
            (0..self.recovery.trash.len()).collect()
        };
        let mut removed = Vec::with_capacity(indexes.len());
        for index in indexes.into_iter().rev() {
            removed.push((index, self.recovery.trash.remove(index)));
        }
        removed.reverse();
        let removed_ids: HashSet<_> = removed.iter().map(|(_, item)| item.entry.id).collect();
        let mut totp = self.take_totp_records(&removed_ids);
        let mut metadata = self.take_metadata_records(&removed_ids);
        if let Err(error) = write_vault(self, key_pass) {
            Self::restore_indexed(&mut self.recovery.totp, std::mem::take(&mut totp));
            Self::restore_indexed(
                &mut self.recovery.entry_metadata,
                std::mem::take(&mut metadata),
            );
            Self::restore_indexed(&mut self.recovery.trash, removed);
            return Err(error);
        }
        for (_, mut item) in removed {
            item.zeroize();
        }
        for (_, mut record) in totp {
            record.zeroize();
        }
        for (_, mut record) in metadata {
            record.zeroize();
        }
        Ok(true)
    }

    pub fn purge_expired_trash(
        &mut self,
        retention_days: u64,
        key_pass: &mut ServerInfo,
    ) -> Result<usize, String> {
        if retention_days == 0 || self.recovery.trash.is_empty() {
            return Ok(0);
        }
        let max_days = i64::MAX / 86_400;
        let days = i64::try_from(retention_days)
            .unwrap_or(max_days)
            .min(max_days);
        let cutoff = chrono::Utc::now()
            .checked_sub_signed(chrono::Duration::days(days))
            .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC);
        let removed_ids = self
            .recovery
            .trash
            .iter()
            .filter_map(|item| {
                chrono::DateTime::parse_from_str(&item.deleted, "%Y-%m-%d %H:%M:%S%.f %:z")
                    .ok()
                    .filter(|deleted| deleted.with_timezone(&chrono::Utc) <= cutoff)
                    .map(|_| item.entry.id)
            })
            .collect::<Vec<_>>();
        if removed_ids.is_empty() {
            return Ok(0);
        }
        let removed_ids: HashSet<_> = removed_ids.into_iter().collect();
        let mut removed = Vec::new();
        let mut retained = Vec::with_capacity(self.recovery.trash.len() - removed_ids.len());
        for (index, item) in std::mem::take(&mut self.recovery.trash)
            .into_iter()
            .enumerate()
        {
            if removed_ids.contains(&item.entry.id) {
                removed.push((index, item));
            } else {
                retained.push(item);
            }
        }
        self.recovery.trash = retained;
        let mut totp = self.take_totp_records(&removed_ids);
        let mut metadata = self.take_metadata_records(&removed_ids);
        if let Err(error) = write_vault(self, key_pass) {
            Self::restore_indexed(&mut self.recovery.totp, std::mem::take(&mut totp));
            Self::restore_indexed(
                &mut self.recovery.entry_metadata,
                std::mem::take(&mut metadata),
            );
            Self::restore_indexed(&mut self.recovery.trash, removed);
            return Err(error);
        }
        for (_, mut item) in removed {
            item.zeroize();
        }
        for (_, mut record) in totp {
            record.zeroize();
        }
        for (_, mut record) in metadata {
            record.zeroize();
        }
        Ok(removed_ids.len())
    }

    fn take_totp_records(&mut self, entry_ids: &HashSet<usize>) -> Vec<(usize, TotpRecord)> {
        let mut removed = Vec::new();
        let mut retained = Vec::with_capacity(self.recovery.totp.len());
        for (index, record) in std::mem::take(&mut self.recovery.totp)
            .into_iter()
            .enumerate()
        {
            if entry_ids.contains(&record.entry_id) {
                removed.push((index, record));
            } else {
                retained.push(record);
            }
        }
        self.recovery.totp = retained;
        removed
    }

    fn take_metadata_records(&mut self, entry_ids: &HashSet<usize>) -> Vec<(usize, EntryMetadata)> {
        let mut removed = Vec::new();
        let mut retained = Vec::with_capacity(self.recovery.entry_metadata.len());
        for (index, record) in std::mem::take(&mut self.recovery.entry_metadata)
            .into_iter()
            .enumerate()
        {
            if entry_ids.contains(&record.entry_id) {
                removed.push((index, record));
            } else {
                retained.push(record);
            }
        }
        self.recovery.entry_metadata = retained;
        removed
    }

    fn restore_indexed<T>(target: &mut Vec<T>, records: Vec<(usize, T)>) {
        for (index, record) in records {
            target.insert(index.min(target.len()), record);
        }
    }

    fn remove_totp_records(&mut self, entry_ids: &[usize]) {
        let mut retained = Vec::with_capacity(self.recovery.totp.len());
        for mut record in std::mem::take(&mut self.recovery.totp) {
            if entry_ids.contains(&record.entry_id) {
                record.zeroize();
            } else {
                retained.push(record);
            }
        }
        self.recovery.totp = retained;
    }

    fn remove_metadata_records(&mut self, entry_ids: &[usize]) {
        let mut retained = Vec::with_capacity(self.recovery.entry_metadata.len());
        for mut record in std::mem::take(&mut self.recovery.entry_metadata) {
            if entry_ids.contains(&record.entry_id) {
                record.zeroize();
            } else {
                retained.push(record);
            }
        }
        self.recovery.entry_metadata = retained;
    }

    fn totp_marker(&self, entry_id: usize) -> &'static str {
        if self
            .recovery
            .totp
            .iter()
            .any(|record| record.entry_id == entry_id)
        {
            " [TOTP]"
        } else {
            ""
        }
    }

    pub(crate) fn audit_snapshot(&self, options: &AuditOptions) -> AuditSnapshot {
        let metadata_by_id: HashMap<_, _> = self
            .recovery
            .entry_metadata
            .iter()
            .map(|record| (record.entry_id, record))
            .collect();
        let totp_ids: HashSet<_> = self
            .recovery
            .totp
            .iter()
            .map(|record| record.entry_id)
            .collect();
        let entries = self
            .entries
            .iter()
            .filter(|entry| {
                metadata_by_id
                    .get(&entry.id)
                    .is_none_or(|metadata| metadata.kind == ItemKind::Login)
            })
            .map(|entry| AuditEntrySnapshot {
                id: entry.id,
                name: entry.name.clone(),
                username: entry.username.clone(),
                password_hash: password_hash(&entry.password),
                weak: zxcvbn::zxcvbn(&entry.password, &[]).score() <= zxcvbn::Score::Two,
                stale: options
                    .stale_days
                    .is_some_and(|days| self.password_is_stale(entry, days)),
                password_changed: self.password_changed(entry).to_string(),
                missing_totp: options.require_totp && !totp_ids.contains(&entry.id),
                identity: (
                    entry
                        .url
                        .as_deref()
                        .and_then(hostname)
                        .unwrap_or_else(|| entry.name.to_ascii_lowercase()),
                    entry.username.as_deref().unwrap_or("").to_ascii_lowercase(),
                ),
            })
            .collect();
        AuditSnapshot { entries }
    }

    fn is_weak(&self, entry: &VaultEntry) -> bool {
        !entry.password.is_empty()
            && run_blocking_io(|| zxcvbn::zxcvbn(&entry.password, &[]).score())
                <= zxcvbn::Score::Two
    }

    fn apply_list_options<'a>(
        &'a self,
        mut entries: Vec<&'a VaultEntry>,
        options: &ListOptions,
    ) -> Vec<&'a VaultEntry> {
        let metadata_by_id: HashMap<_, _> = self
            .recovery
            .entry_metadata
            .iter()
            .map(|record| (record.entry_id, record))
            .collect();
        let totp_ids: HashSet<_> = self
            .recovery
            .totp
            .iter()
            .map(|record| record.entry_id)
            .collect();
        entries.retain(|entry| {
            options.kind.is_none_or(|kind| {
                metadata_by_id
                    .get(&entry.id)
                    .map_or(ItemKind::Login, |metadata| metadata.kind)
                    == kind
            }) && options
                .has_totp
                .is_none_or(|expected| totp_ids.contains(&entry.id) == expected)
                && (!options.weak || self.is_weak(entry))
                && options
                    .stale_days
                    .is_none_or(|days| self.password_is_stale(entry, days))
        });
        if options.sort == SortField::Name {
            if options.descending {
                entries.sort_by_cached_key(|entry| std::cmp::Reverse(entry.name.to_lowercase()));
            } else {
                entries.sort_by_cached_key(|entry| entry.name.to_lowercase());
            }
        } else {
            entries.sort_by(|left, right| {
                let ordering = match options.sort {
                    SortField::Id => left.id.cmp(&right.id),
                    SortField::Created => left.created.cmp(&right.created),
                    SortField::Modified => left.modified.cmp(&right.modified),
                    SortField::PasswordAge => self
                        .password_changed_with_metadata(left, metadata_by_id.get(&left.id).copied())
                        .cmp(self.password_changed_with_metadata(
                            right,
                            metadata_by_id.get(&right.id).copied(),
                        )),
                    SortField::Name => unreachable!("name sorting uses cached lowercase keys"),
                };
                if options.descending {
                    ordering.reverse()
                } else {
                    ordering
                }
            });
        }
        entries
    }

    fn password_changed_with_metadata<'a>(
        &'a self,
        entry: &'a VaultEntry,
        metadata: Option<&'a EntryMetadata>,
    ) -> &'a str {
        metadata
            .and_then(|record| record.password_changed.as_deref())
            .unwrap_or(&entry.created)
    }

    fn entry_summary(&self, entry: &VaultEntry) -> String {
        let metadata_by_id: HashMap<_, _> = self
            .recovery
            .entry_metadata
            .iter()
            .map(|record| (record.entry_id, record))
            .collect();
        let totp_ids: HashSet<_> = self
            .recovery
            .totp
            .iter()
            .map(|record| record.entry_id)
            .collect();
        self.entry_summary_indexed(entry, &metadata_by_id, &totp_ids)
    }

    fn entry_summary_indexed(
        &self,
        entry: &VaultEntry,
        metadata_by_id: &HashMap<usize, &EntryMetadata>,
        totp_ids: &HashSet<usize>,
    ) -> String {
        let metadata = metadata_by_id.get(&entry.id).copied();
        let totp = if totp_ids.contains(&entry.id) {
            " [TOTP]"
        } else {
            ""
        };
        let urls = entry
            .url
            .as_deref()
            .into_iter()
            .chain(
                metadata
                    .into_iter()
                    .flat_map(|record| record.additional_urls.iter().map(String::as_str)),
            )
            .collect::<Vec<_>>()
            .join(", ");
        let fields = metadata
            .map_or(&[][..], |record| record.custom_fields.as_slice())
            .iter()
            .map(|field| {
                if field.secret {
                    format!("{} [secret]", field.name)
                } else {
                    format!("{}={}", field.name, field.value)
                }
            })
            .collect::<Vec<_>>();
        format!(
            "{}. {} [{}] {:?} {:?} {:?} {:?}{}\n",
            entry.id,
            entry.name,
            metadata.map_or(ItemKind::Login, |record| record.kind),
            entry.username,
            (!urls.is_empty()).then_some(urls),
            entry.notes,
            fields,
            totp
        )
    }

    pub async fn view_entries(&self, options: ListOptions, stream: &mut TcpStream) {
        if self.entries.is_empty() {
            respond("No entries.", stream).await;
            return;
        }
        let entries = self.apply_list_options(self.entries.iter().collect(), &options);
        if entries.is_empty() {
            respond_with_code(ResponseCode::NotFound, "No matching entries.", stream).await;
            return;
        }
        let metadata_by_id: HashMap<_, _> = self
            .recovery
            .entry_metadata
            .iter()
            .map(|record| (record.entry_id, record))
            .collect();
        let totp_ids: HashSet<_> = self
            .recovery
            .totp
            .iter()
            .map(|record| record.entry_id)
            .collect();
        for entry in entries {
            respond(
                &self.entry_summary_indexed(entry, &metadata_by_id, &totp_ids),
                stream,
            )
            .await;
        }
    }

    fn browser_autofill_json(&self) -> String {
        let metadata_by_id: HashMap<_, _> = self
            .recovery
            .entry_metadata
            .iter()
            .map(|record| (record.entry_id, record))
            .collect();
        let items = self
            .entries
            .iter()
            .filter_map(|entry| {
                let kind = metadata_by_id
                    .get(&entry.id)
                    .map_or(ItemKind::Login, |metadata| metadata.kind);
                matches!(kind, ItemKind::PaymentCard | ItemKind::Identity).then(|| {
                    json!({
                        "id": entry.id,
                        "name": entry.name,
                        "kind": kind,
                        "username": entry.username,
                    })
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_string(&items).expect("browser autofill items are serializable")
    }

    pub async fn browser_autofill(&self, stream: &mut TcpStream) {
        respond(&self.browser_autofill_json(), stream).await;
    }

    fn browser_autofill_item_json(&self, id: usize) -> Option<String> {
        let entry = self.entries.iter().find(|entry| entry.id == id)?;
        let kind = self.item_kind(entry.id);
        if !matches!(kind, ItemKind::PaymentCard | ItemKind::Identity) {
            return None;
        }
        Some(
            json!({
                "id": entry.id,
                "name": entry.name,
                "kind": kind,
                "username": entry.username,
                "primary_secret": entry.password,
                "custom_fields": self.custom_fields(entry.id),
            })
            .to_string(),
        )
    }

    pub async fn browser_autofill_item(&self, id: usize, stream: &mut TcpStream) {
        if let Some(item) = self.browser_autofill_item_json(id) {
            respond(&item, stream).await;
        } else {
            respond_with_code(ResponseCode::NotFound, "Autofill item not found.", stream).await;
        }
    }

    fn search_entries(&self, filter: &SearchFilter) -> Vec<&VaultEntry> {
        fn field_matches(value: Option<&str>, needle: Option<&String>) -> bool {
            needle.is_none_or(|needle| {
                value.is_some_and(|value| value.to_lowercase().contains(needle))
            })
        }

        let query = filter.query.as_ref().map(|query| query.to_lowercase());
        let name = filter.name.as_ref().map(|value| value.to_lowercase());
        let username = filter.username.as_ref().map(|value| value.to_lowercase());
        let url = filter.url.as_ref().map(|value| value.to_lowercase());
        let notes = filter.notes.as_ref().map(|value| value.to_lowercase());
        let metadata_by_id: HashMap<_, _> = self
            .recovery
            .entry_metadata
            .iter()
            .map(|record| (record.entry_id, record))
            .collect();
        self.entries
            .iter()
            .filter(|entry| {
                let query_matches =
                    query.as_ref().is_none_or(|query| {
                        entry.name.to_lowercase().contains(query)
                            || entry
                                .username
                                .as_deref()
                                .is_some_and(|value| value.to_lowercase().contains(query))
                            || entry
                                .url
                                .as_deref()
                                .into_iter()
                                .chain(metadata_by_id.get(&entry.id).into_iter().flat_map(
                                    |record| record.additional_urls.iter().map(String::as_str),
                                ))
                                .any(|value| value.to_lowercase().contains(query))
                            || entry
                                .notes
                                .as_deref()
                                .is_some_and(|value| value.to_lowercase().contains(query))
                            || metadata_by_id
                                .get(&entry.id)
                                .into_iter()
                                .flat_map(|record| &record.custom_fields)
                                .any(|field| {
                                    field.name.to_lowercase().contains(query)
                                        || (!field.secret
                                            && field.value.to_lowercase().contains(query))
                                })
                    });
                query_matches
                    && field_matches(Some(&entry.name), name.as_ref())
                    && field_matches(entry.username.as_deref(), username.as_ref())
                    && url.as_ref().is_none_or(|needle| {
                        entry
                            .url
                            .as_deref()
                            .into_iter()
                            .chain(
                                metadata_by_id
                                    .get(&entry.id)
                                    .into_iter()
                                    .flat_map(|record| {
                                        record.additional_urls.iter().map(String::as_str)
                                    }),
                            )
                            .any(|url| url.to_lowercase().contains(needle))
                    })
                    && field_matches(entry.notes.as_deref(), notes.as_ref())
            })
            .collect()
    }

    pub async fn search(&self, filter: SearchFilter, stream: &mut TcpStream) {
        let entries = self.apply_list_options(self.search_entries(&filter), &filter.list);
        if entries.is_empty() {
            respond_with_code(ResponseCode::NotFound, "No matching entries.", stream).await;
            return;
        }
        for entry in entries {
            respond(&self.entry_summary(entry), stream).await;
        }
    }

    pub fn lock_vault(&self, key_pass: &mut ServerInfo) -> Result<(), String> {
        write_vault(self, key_pass)?;
        key_pass.zeroize();
        Ok(())
    }
    pub fn export(&self, path: String, force: bool) -> Result<(), String> {
        if std::path::Path::new(&path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        {
            let metadata_by_id: HashMap<_, _> = self
                .recovery
                .entry_metadata
                .iter()
                .map(|record| (record.entry_id, record))
                .collect();
            let totp_by_id: HashMap<_, _> = self
                .recovery
                .totp
                .iter()
                .map(|record| (record.entry_id, record))
                .collect();
            let mut history_by_id: HashMap<usize, Vec<&PasswordRevision>> = HashMap::new();
            for revision in &self.recovery.password_history {
                history_by_id
                    .entry(revision.entry_id)
                    .or_default()
                    .push(revision);
            }
            let items = self
                .entries
                .iter()
                .map(|entry| {
                    let metadata = metadata_by_id.get(&entry.id).copied();
                    PortableItem {
                        id: entry.id,
                        name: entry.name.clone(),
                        username: entry.username.clone(),
                        password: entry.password.clone(),
                        url: entry.url.clone(),
                        notes: entry.notes.clone(),
                        created: entry.created.clone(),
                        modified: entry.modified.clone(),
                        kind: self.item_kind(entry.id),
                        additional_urls: metadata
                            .map(|record| record.additional_urls.clone())
                            .unwrap_or_default(),
                        custom_fields: metadata
                            .map(|record| record.custom_fields.clone())
                            .unwrap_or_default(),
                        password_changed: metadata
                            .and_then(|record| record.password_changed.clone()),
                        password_history: history_by_id
                            .get(&entry.id)
                            .into_iter()
                            .flatten()
                            .map(|revision| PortableRevision {
                                password: revision.password.clone(),
                                changed: revision.changed.clone(),
                            })
                            .collect(),
                        totp: totp_by_id
                            .get(&entry.id)
                            .map(|record| record.configuration.clone()),
                    }
                })
                .collect();
            let mut export = PortableExport {
                format: PORTABLE_FORMAT.to_string(),
                version: PORTABLE_VERSION,
                exported_at: chrono::Utc::now().to_rfc3339(),
                items,
            };
            let encoded = serde_json::to_vec_pretty(&export);
            export.zeroize();
            let mut encoded = encoded.map_err(|e| format!("could not encode JSON export: {e}"))?;
            let result = persist_private_file(Path::new(&path), &encoded, force)
                .map_err(|e| format!("could not create export file {path:?}: {e}"));
            encoded.zeroize();
            return result;
        }
        let mut wtr = csv::Writer::from_writer(Vec::new());
        for i in &self.entries {
            wtr.serialize(i)
                .map_err(|e| format!("could not write export file {path:?}: {e}"))?;
        }
        let mut encoded = wtr
            .into_inner()
            .map_err(|e| format!("could not finish export file {path:?}: {}", e.error()))?;
        let result = persist_private_file(Path::new(&path), &encoded, force)
            .map_err(|e| format!("could not create export file {path:?}: {e}"));
        encoded.zeroize();
        result
    }

    pub fn encrypted_backup(
        &self,
        path: String,
        key_pass: &mut PasswordType,
        force: bool,
    ) -> Result<(), String> {
        if let PasswordType::Password(password) = &key_pass
            && let Err(error) = validate_new_password(password)
        {
            key_pass.zeroize();
            return Err(error.to_string());
        }
        let vault_path = data_dir().join(&self.metadata.filename);
        let backup_path = Path::new(&path);
        if backup_path.exists()
            && fs::canonicalize(backup_path).ok() == fs::canonicalize(&vault_path).ok()
        {
            return Err("backup path cannot overwrite the active vault file".to_string());
        }
        let envelope = BackupEnvelopeRef {
            version: BACKUP_VERSION,
            created: chrono::Utc::now().to_rfc3339(),
            vault: self,
        };
        let plaintext = rmp_serde::to_vec(&envelope)
            .map_err(|error| format!("could not encode backup: {error}"))?;
        let mut output = try_encrypt_file_in_place(key_pass, plaintext)?;
        let prefix_len = BACKUP_MAGIC.len() + 1;
        let encrypted_len = output.len();
        output.reserve(prefix_len);
        output.resize(encrypted_len + prefix_len, 0);
        output.copy_within(..encrypted_len, prefix_len);
        output[..BACKUP_MAGIC.len()].copy_from_slice(BACKUP_MAGIC);
        output[BACKUP_MAGIC.len()] = BACKUP_VERSION;
        let result = persist_private_file(backup_path, &output, force);
        output.zeroize();
        result
    }

    fn replace_portable_records(
        &mut self,
        entry_id: usize,
        imported: &mut ImportedItem,
        old_password: Option<String>,
        password_history_limit: usize,
    ) {
        self.remove_metadata_records(&[entry_id]);
        self.remove_totp_records(&[entry_id]);

        let mut retained = Vec::with_capacity(self.recovery.password_history.len());
        for mut revision in std::mem::take(&mut self.recovery.password_history) {
            if revision.entry_id == entry_id {
                revision.zeroize();
            } else {
                retained.push(revision);
            }
        }
        self.recovery.password_history = retained;

        let mut history = std::mem::take(&mut imported.password_history)
            .into_iter()
            .map(|revision| PasswordRevision {
                entry_id,
                password: revision.password,
                changed: revision.changed,
            })
            .collect::<Vec<_>>();
        if let Some(password) = old_password {
            history.push(PasswordRevision {
                entry_id,
                password,
                changed: chrono::Local::now().to_string(),
            });
        }
        if history.len() > password_history_limit {
            let mut removed = history.drain(..history.len() - password_history_limit);
            removed.by_ref().for_each(|revision| {
                let mut revision = revision;
                revision.zeroize();
            });
        }
        self.recovery.password_history.extend(history);

        if imported.kind != ItemKind::Login
            || !imported.additional_urls.is_empty()
            || !imported.custom_fields.is_empty()
            || imported.password_changed.is_some()
        {
            self.recovery.entry_metadata.push(EntryMetadata {
                entry_id,
                kind: imported.kind,
                additional_urls: std::mem::take(&mut imported.additional_urls),
                password_changed: imported.password_changed.take(),
                custom_fields: std::mem::take(&mut imported.custom_fields),
            });
        }
        if let Some(configuration) = imported.totp.take() {
            self.recovery.totp.push(TotpRecord {
                entry_id,
                configuration,
            });
        }
    }

    pub fn import_with_options(
        &mut self,
        path: String,
        conflicts: ConflictPolicy,
        preview: bool,
        password_history_limit: usize,
        key_pass: &mut ServerInfo,
    ) -> Result<ImportReport, String> {
        let metadata = fs::metadata(&path)
            .map_err(|error| format!("could not open import file {path:?}: {error}"))?;
        if !metadata.is_file() {
            return Err(format!("import path {path:?} is not a regular file"));
        }
        if metadata.len() > MAX_IMPORT_BYTES {
            return Err(format!(
                "import file {path:?} exceeds the {} MiB limit",
                MAX_IMPORT_BYTES / (1024 * 1024)
            ));
        }
        let file = fs::File::open(&path)
            .map_err(|error| format!("could not open import file {path:?}: {error}"))?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(metadata.len().min(MAX_IMPORT_BYTES)).unwrap_or_default(),
        );
        file.take(MAX_IMPORT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("could not read import file {path:?}: {error}"))?;
        if bytes.len() as u64 > MAX_IMPORT_BYTES {
            bytes.zeroize();
            return Err(format!(
                "import file {path:?} exceeds the {} MiB limit",
                MAX_IMPORT_BYTES / (1024 * 1024)
            ));
        }
        let contents = match String::from_utf8(bytes) {
            Ok(contents) => Zeroizing::new(contents),
            Err(error) => {
                let mut bytes = error.into_bytes();
                bytes.zeroize();
                return Err(format!("import file {path:?} is not valid UTF-8"));
            }
        };
        let trimmed = contents.trim_start();
        let imported = if trimmed.starts_with('{') || trimmed.starts_with('[') {
            import_json(&contents, &path)?
        } else {
            import_csv(&contents, &path)?
        };
        if imported.len() > MAX_IMPORT_ITEMS {
            return Err(format!(
                "import contains more than the {MAX_IMPORT_ITEMS} item limit"
            ));
        }
        let mut report = ImportReport {
            total: imported.len(),
            preview,
            ..ImportReport::default()
        };
        let mut entries_before = self.entries.clone();
        let mut recovery_before = self.recovery.clone();
        let mut duplicate_index: HashMap<(String, Option<String>, Option<String>), usize> =
            HashMap::with_capacity(self.entries.len());
        for (index, entry) in self.entries.iter().enumerate() {
            duplicate_index
                .entry((
                    entry.name.clone(),
                    entry.username.clone(),
                    entry.url.clone(),
                ))
                .or_insert(index);
        }
        let mut name_index: HashSet<(String, Option<String>)> = self
            .entries
            .iter()
            .map(|entry| (entry.name.clone(), entry.username.clone()))
            .collect();
        for mut imported in imported {
            let duplicate_key = (
                imported.entry.name.clone(),
                imported.entry.username.clone(),
                imported.entry.url.clone(),
            );
            let duplicate = duplicate_index.get(&duplicate_key).copied();
            match (duplicate, conflicts) {
                (Some(_), ConflictPolicy::Skip) => report.skipped += 1,
                (Some(index), ConflictPolicy::Replace) => {
                    report.replaced += 1;
                    if !preview {
                        let id = self.entries[index].id;
                        let created = self.entries[index].created.clone();
                        let old_password = (self.entries[index].password
                            != imported.entry.password)
                            .then(|| self.entries[index].password.clone());
                        imported.entry.id = id;
                        imported.entry.created = created;
                        imported.entry.modified = chrono::Local::now().to_string();
                        self.entries[index].zeroize();
                        self.entries[index] = std::mem::take(&mut imported.entry);
                        if imported.portable {
                            self.replace_portable_records(
                                id,
                                &mut imported,
                                old_password,
                                password_history_limit,
                            );
                        } else if let Some(password) = old_password {
                            self.push_password_history_with_limit(
                                id,
                                password,
                                password_history_limit,
                            );
                        }
                    }
                }
                (Some(_), ConflictPolicy::KeepBoth) => {
                    report.added += 1;
                    report.renamed += 1;
                    if !preview {
                        let base = imported.entry.name.clone();
                        let mut suffix = 1usize;
                        loop {
                            let candidate = if suffix == 1 {
                                format!("{base} (imported)")
                            } else {
                                format!("{base} (imported {suffix})")
                            };
                            if !name_index
                                .contains(&(candidate.clone(), imported.entry.username.clone()))
                            {
                                imported.entry.name = candidate;
                                break;
                            }
                            suffix += 1;
                        }
                        let id = self.allocate_entry_id()?;
                        imported.entry.id = id;
                        self.entries.push(std::mem::take(&mut imported.entry));
                        let added = self.entries.last().expect("imported entry was just added");
                        name_index.insert((added.name.clone(), added.username.clone()));
                        duplicate_index.insert(
                            (
                                added.name.clone(),
                                added.username.clone(),
                                added.url.clone(),
                            ),
                            self.entries.len() - 1,
                        );
                        if imported.portable {
                            self.replace_portable_records(
                                id,
                                &mut imported,
                                None,
                                password_history_limit,
                            );
                        }
                    }
                }
                (None, _) => {
                    report.added += 1;
                    if !preview {
                        let id = self.allocate_entry_id()?;
                        imported.entry.id = id;
                        self.entries.push(std::mem::take(&mut imported.entry));
                        let added = self.entries.last().expect("imported entry was just added");
                        name_index.insert((added.name.clone(), added.username.clone()));
                        duplicate_index.insert(
                            (
                                added.name.clone(),
                                added.username.clone(),
                                added.url.clone(),
                            ),
                            self.entries.len() - 1,
                        );
                        if imported.portable {
                            self.replace_portable_records(
                                id,
                                &mut imported,
                                None,
                                password_history_limit,
                            );
                        }
                    }
                }
            }
        }
        if !preview && let Err(error) = write_vault(self, key_pass) {
            self.entries.zeroize();
            self.entries = std::mem::take(&mut entries_before);
            self.recovery.zeroize();
            self.recovery = std::mem::take(&mut recovery_before);
            return Err(error);
        }
        entries_before.zeroize();
        recovery_before.zeroize();
        Ok(report)
    }
}

fn apply_update(entry: &mut VaultEntry, update: UpdateArgs, password: Option<String>) -> bool {
    let mut modified = false;
    if let Some(name) = update.name {
        entry.name = name;
        modified = true;
    }
    if let Some(notes) = update.notes {
        entry.notes = (!notes.is_empty()).then_some(notes);
        modified = true;
    }
    if update.password
        && let Some(password) = password
    {
        entry.password = password;
        modified = true;
    }
    if let Some(url) = update.url {
        entry.url = Some(url);
        modified = true;
    }
    if let Some(username) = update.username {
        entry.username = (!username.is_empty()).then_some(username);
        modified = true;
    }
    if modified {
        entry.modified = chrono::Local::now().to_string();
    }
    modified
}

pub trait VaultAccess {
    async fn get_entry(&self, a: Target, stream: &mut TcpStream);
    async fn get_secret(&self, target: Target, stream: &mut TcpStream);
    fn add_entry(&mut self, info: PasswordEntry, key_pass: &mut ServerInfo)
    -> Result<bool, String>;
    fn add_typed_entry(
        &mut self,
        info: TypedEntry,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String>;
    fn delete_entry(&mut self, id: Target, key_pass: &mut ServerInfo) -> Result<bool, String>;
    fn update_entry_with_limit(
        &mut self,
        update: EntryUpdate,
        key_pass: &mut ServerInfo,
        password_history_limit: usize,
    ) -> Result<bool, String>;
    fn update_typed_entry_with_limit(
        &mut self,
        update: TypedUpdate,
        key_pass: &mut ServerInfo,
        password_history_limit: usize,
    ) -> Result<bool, String>;
    async fn view_entries(&self, options: ListOptions, stream: &mut TcpStream);
    fn lock_vault(&self, key_pass: &mut ServerInfo) -> Result<(), String>;
    fn unlock_vault(&mut self, key_pass: &mut ServerInfo) -> Result<(), String>;
    fn export(&self, path: String, force: bool) -> Result<(), String>;
    fn import_with_options(
        &mut self,
        path: String,
        conflicts: ConflictPolicy,
        preview: bool,
        password_history_limit: usize,
        key_pass: &mut ServerInfo,
    ) -> Result<ImportReport, String>;
}

impl VaultAccess for Option<Vault> {
    async fn get_entry(&self, a: Target, stream: &mut TcpStream) {
        if let Some(vlt) = self {
            vlt.get_entry(a, stream).await
        }
    }
    async fn get_secret(&self, target: Target, stream: &mut TcpStream) {
        if let Some(vault) = self {
            vault.get_secret(target, stream).await;
        }
    }
    fn add_entry(
        &mut self,
        info: PasswordEntry,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        match self {
            Some(vlt) => vlt.add_entry(info, key_pass),
            None => Err("vault is locked".to_string()),
        }
    }
    fn add_typed_entry(
        &mut self,
        info: TypedEntry,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        match self {
            Some(vlt) => vlt.add_typed_entry(info, key_pass),
            None => Err("vault is locked".to_string()),
        }
    }
    fn delete_entry(&mut self, id: Target, key_pass: &mut ServerInfo) -> Result<bool, String> {
        match self {
            Some(vlt) => vlt.delete_entry(id, key_pass),
            None => Err("vault is locked".to_string()),
        }
    }

    fn update_entry_with_limit(
        &mut self,
        update: EntryUpdate,
        key_pass: &mut ServerInfo,
        password_history_limit: usize,
    ) -> Result<bool, String> {
        match self {
            Some(vault) => vault.update_entry_with_limit(update, key_pass, password_history_limit),
            None => Err("vault is locked".to_string()),
        }
    }
    fn update_typed_entry_with_limit(
        &mut self,
        update: TypedUpdate,
        key_pass: &mut ServerInfo,
        password_history_limit: usize,
    ) -> Result<bool, String> {
        match self {
            Some(vault) => {
                vault.update_typed_entry_with_limit(update, key_pass, password_history_limit)
            }
            None => Err("vault is locked".to_string()),
        }
    }
    async fn view_entries(&self, options: ListOptions, stream: &mut TcpStream) {
        if let Some(vlt) = self {
            vlt.view_entries(options, stream).await;
        }
    }
    fn lock_vault(&self, key_pass: &mut ServerInfo) -> Result<(), String> {
        if let Some(vlt) = self {
            vlt.lock_vault(key_pass)?;
        }
        key_pass.zeroize();
        Ok(())
    }
    fn unlock_vault(&mut self, key_pass: &mut ServerInfo) -> Result<(), String> {
        if self.is_some() {
            return Err(
                "a vault is already unlocked; lock it before unlocking another one".to_string(),
            );
        }
        match crate::vault::unlock_vault(key_pass) {
            Some(vault) => {
                *self = Some(vault);
                Ok(())
            }
            None => Err("wrong master password, or no vault exists for this key".to_string()),
        }
    }
    fn export(&self, path: String, force: bool) -> Result<(), String> {
        if let Some(vlt) = self {
            vlt.export(path, force)
        } else {
            Err("vault is locked".to_string())
        }
    }
    fn import_with_options(
        &mut self,
        path: String,
        conflicts: ConflictPolicy,
        preview: bool,
        password_history_limit: usize,
        key_pass: &mut ServerInfo,
    ) -> Result<ImportReport, String> {
        match self {
            Some(vault) => vault.import_with_options(
                path,
                conflicts,
                preview,
                password_history_limit,
                key_pass,
            ),
            None => Err("vault is locked".to_string()),
        }
    }
}
pub fn delete_vault(mut key: PasswordType, keep_key: bool) -> Result<(), String> {
    let data = data_dir();
    let key_to_remove = match &key {
        PasswordType::Key(path) if !keep_key => Some(path.clone()),
        _ => None,
    };
    if let PasswordType::Key(key_path) = &key
        && !key_file_path(key_path)?.is_file()
    {
        return Err("key file does not exist or is not a regular file".to_string());
    }
    let (filename, mut vault) = find_vault(&mut key)
        .ok_or_else(|| "could not delete vault (is the key correct?)".to_string())?;
    vault.zeroize();
    fs::remove_file(data.join(filename))
        .map_err(|e| format!("could not delete vault (is the key correct?): {e}"))?;
    if let Some(mut key) = key_to_remove {
        fs::remove_file(key_file_path(&key)?)
            .map_err(|e| format!("vault deleted, but could not delete its key file: {e}"))?;
        key.zeroize();
    }
    key.zeroize();
    Ok(())
}
#[cfg(test)]
#[path = "vault_tests.rs"]
mod test;
