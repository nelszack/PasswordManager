use crate::{
    clipboard::copy_in_background,
    encryption::{decrypt_file, try_encrypt_file, try_gen_master_key, try_gen_master_key_legacy},
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
    io::Write,
    path::Path,
};
use tempfile::NamedTempFile;
use tokio::net::TcpStream;
use totp_rs::{Builder as TotpBuilder, Secret as TotpSecret, Totp, TotpError};
use zeroize::{Zeroize, Zeroizing};

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
    #[serde(default)]
    pub kind: ItemKind,
    #[serde(default)]
    pub additional_urls: Vec<String>,
    #[serde(default)]
    pub password_changed: Option<String>,
    #[serde(default)]
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
    #[serde(default)]
    pub next_entry_id: usize,
    #[serde(default)]
    pub totp: Vec<TotpRecord>,
    #[serde(default)]
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
    #[serde(alias = "enteries")]
    pub entries: Vec<VaultEntry>,
    pub metadata: VaultMetadata,
    #[serde(default)]
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
    #[serde(rename = "type", default)]
    kind: ItemKind,
    #[serde(default)]
    additional_urls: Vec<String>,
    #[serde(default)]
    custom_fields: Vec<CustomField>,
    #[serde(default)]
    password_changed: Option<String>,
    #[serde(default)]
    password_history: Vec<PortableRevision>,
    #[serde(default)]
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

fn filename_key_from_master(master_key: &[u8; 32]) -> [u8; 32] {
    blake3::derive_key("vault-filename-v1", master_key)
}

fn vault_filename_from_key(filename_key: &[u8; 32]) -> String {
    let hash = blake3::hash(filename_key);
    let short = &hash.as_bytes()[..16];
    format!("{}.enc", hex::encode(short))
}

fn random_vault_filename() -> String {
    loop {
        let filename = format!("{}.enc", hex::encode(rand::random::<[u8; 16]>()));
        if !data_dir().join(&filename).exists() {
            return filename;
        }
    }
}

fn try_get_deterministic_filename(key_pass: &mut PasswordType) -> Result<String, String> {
    let mut master_key = try_gen_master_key(key_pass, false)?;
    let mut filename_key = filename_key_from_master(&master_key);
    master_key.zeroize();
    let filename = vault_filename_from_key(&filename_key);
    filename_key.zeroize();
    Ok(filename)
}

fn try_get_legacy_filename(key_pass: &mut PasswordType) -> Result<String, String> {
    let mut master_key = try_gen_master_key_legacy(key_pass)?;
    let mut filename_key = filename_key_from_master(&master_key);
    master_key.zeroize();
    let filename = vault_filename_from_key(&filename_key);
    filename_key.zeroize();
    Ok(filename)
}

fn find_vault(key_pass: &mut PasswordType) -> Option<(String, Vault, bool)> {
    let deterministic = try_get_deterministic_filename(key_pass).ok();
    let legacy = try_get_legacy_filename(key_pass).ok();
    let mut candidates: Vec<String> = deterministic.iter().chain(legacy.iter()).cloned().collect();
    if let Ok(entries) = fs::read_dir(data_dir()) {
        candidates.extend(
            entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|name| name.ends_with(".enc")),
        );
    }
    let mut seen = HashSet::new();
    candidates.retain(|candidate| seen.insert(candidate.clone()));

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
        let needs_migration =
            deterministic.as_ref() == Some(&filename) || legacy.as_ref() == Some(&filename);
        vault.metadata.filename = filename.clone();
        return Some((filename, vault, needs_migration));
    }
    None
}

pub fn create_vault(
    vlt: &mut Option<Vault>,
    server_info: &mut ServerInfo,
    lock: bool,
) -> Result<(), String> {
    let generated_key_path = match server_info.keypass.as_ref() {
        Some(PasswordType::Key(path)) if !new_key_file_path(path)?.exists() => {
            Some(new_key_file_path(path)?)
        }
        _ => None,
    };
    if matches!(server_info.keypass, Some(PasswordType::Key(_))) {
        let mut key = try_gen_master_key(server_info.keypass.as_mut().unwrap(), true)?;
        key.zeroize();
    } else if find_vault(server_info.keypass.as_mut().unwrap()).is_some() {
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
    let mut buf = rmp_serde::to_vec(&vlt).map_err(|e| format!("could not encode vault: {e}"))?;
    let mut txt = match try_encrypt_file(key_pass, &buf[..]) {
        Ok(encrypted) => encrypted,
        Err(error) => {
            buf.zeroize();
            return Err(error);
        }
    };
    let result = (|| {
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
    })();
    buf.zeroize();
    txt.zeroize();
    result
}

fn persist_private_file(path: &Path, contents: &[u8], force: bool) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
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
                    "backup file {:?} already exists; use --force to replace it",
                    path
                )
            } else {
                format!("could not create private file: {}", error.error)
            }
        })?;
    }
    sync_parent(path).map_err(|error| format!("could not sync private file directory: {error}"))?;
    Ok(())
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
        let existing = find_vault(key_pass).map(|(filename, mut vault, _)| {
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
    let (filename, mut vault, needs_migration) = find_vault(key_pass.keypass.as_mut().unwrap())?;
    if needs_migration {
        let preferred = random_vault_filename();
        let file_path = data_dir().join(&filename);
        {
            let old_metadata_filename = vault.metadata.filename.clone();
            vault.metadata.filename = preferred.clone();
            if write_vault_with_key(&vault, key_pass.keypass.as_mut().unwrap()).is_ok() {
                let _ = fs::remove_file(&file_path);
            } else {
                vault.metadata.filename = old_metadata_filename;
            }
        }
    }
    key_pass.locked = false;
    Some(vault)
}

fn url_match_json(
    entries: &[VaultEntry],
    totp_records: &[TotpRecord],
    metadata: &[EntryMetadata],
    url: &str,
) -> Option<String> {
    let mut results = Vec::new();
    for e in entries {
        let item_metadata = metadata.iter().find(|record| record.entry_id == e.id);
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
                "has_totp": totp_records.iter().any(|record| record.entry_id == e.id),
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

fn password_hash(password: &str) -> String {
    hex::encode_upper(Sha1::digest(password.as_bytes()))
}

fn parse_pwned_range(body: &str, prefix: &str) -> HashMap<String, u64> {
    body.lines()
        .filter_map(|line| {
            let (suffix, count) = line.trim().split_once(':')?;
            let count = count.parse::<u64>().ok()?;
            (count > 0).then(|| (format!("{prefix}{}", suffix.to_ascii_uppercase()), count))
        })
        .collect()
}

async fn breached_hashes<'a>(
    passwords: impl Iterator<Item = &'a str>,
) -> Result<HashMap<String, u64>, String> {
    let mut prefixes = HashSet::new();
    for password in passwords {
        prefixes.insert(password_hash(password)[..5].to_string());
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent("password-manager/0.1 breach-audit")
        .build()
        .map_err(|error| format!("could not initialize breach checker: {error}"))?;
    const MAX_CONCURRENT_REQUESTS: usize = 8;
    let mut pending = prefixes.into_iter();
    let mut requests = tokio::task::JoinSet::new();
    for prefix in pending.by_ref().take(MAX_CONCURRENT_REQUESTS) {
        requests.spawn(fetch_breached_prefix(client.clone(), prefix));
    }

    let mut matches = HashMap::new();
    while let Some(result) = requests.join_next().await {
        let prefix_matches =
            result.map_err(|error| format!("breach-check task failed: {error}"))??;
        matches.extend(prefix_matches);
        if let Some(prefix) = pending.next() {
            requests.spawn(fetch_breached_prefix(client.clone(), prefix));
        }
    }
    Ok(matches)
}

async fn fetch_breached_prefix(
    client: reqwest::Client,
    prefix: String,
) -> Result<HashMap<String, u64>, String> {
    const MAX_RANGE_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
    let response = client
        .get(format!("https://api.pwnedpasswords.com/range/{prefix}"))
        .header("Add-Padding", "true")
        .send()
        .await
        .map_err(|error| format!("Pwned Passwords request failed: {error}"))?
        .error_for_status()
        .map_err(|error| format!("Pwned Passwords returned an error: {error}"))?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RANGE_RESPONSE_BYTES)
    {
        return Err("Pwned Passwords returned an oversized response".to_string());
    }
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| format!("could not read Pwned Passwords response: {error}"))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RANGE_RESPONSE_BYTES as usize {
            body.zeroize();
            return Err("Pwned Passwords returned an oversized response".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    let text = match std::str::from_utf8(&body) {
        Ok(text) => text,
        Err(error) => {
            body.zeroize();
            return Err(format!("Pwned Passwords returned invalid UTF-8: {error}"));
        }
    };
    let matches = parse_pwned_range(text, &prefix);
    body.zeroize();
    Ok(matches)
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

fn normalized_header(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn csv_field(headers: &[String], record: &csv::StringRecord, aliases: &[&str]) -> Option<String> {
    headers
        .iter()
        .position(|header| aliases.contains(&header.as_str()))
        .and_then(|index| record.get(index))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn import_csv(contents: &str, path: &str) -> Result<Vec<ImportedItem>, String> {
    let mut reader = csv::Reader::from_reader(contents.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| format!("invalid CSV headers in {path:?}: {e}"))?
        .iter()
        .map(normalized_header)
        .collect();
    let mut entries = Vec::new();
    for row in reader.records() {
        let row = row.map_err(|e| format!("invalid CSV data in {path:?}: {e}"))?;
        let name = csv_field(&headers, &row, &["name", "title"])
            .or_else(|| csv_field(&headers, &row, &["url", "website", "loginuri"]))
            .ok_or_else(|| format!("an imported CSV row in {path:?} has no name or URL"))?;
        let password = csv_field(&headers, &row, &["password"])
            .ok_or_else(|| format!("an imported CSV row in {path:?} has no password"))?;
        let now = chrono::Local::now().to_string();
        entries.push(ImportedItem::login(VaultEntry {
            id: 0,
            name,
            username: csv_field(&headers, &row, &["username", "loginusername", "login"]),
            password,
            url: csv_field(
                &headers,
                &row,
                &["url", "website", "loginuri", "formactionorigin"],
            ),
            notes: csv_field(&headers, &row, &["notes", "note", "extra", "comments"]),
            created: csv_field(&headers, &row, &["created", "timecreated"])
                .unwrap_or_else(|| now.clone()),
            modified: csv_field(
                &headers,
                &row,
                &["modified", "timemodified", "timepasswordchanged"],
            )
            .unwrap_or(now),
        }));
    }
    Ok(entries)
}

fn json_text(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(serde_json::Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn import_json(contents: &str, path: &str) -> Result<Vec<ImportedItem>, String> {
    let root: serde_json::Value =
        serde_json::from_str(contents).map_err(|e| format!("invalid JSON in {path:?}: {e}"))?;
    if root.get("format").and_then(serde_json::Value::as_str) == Some(PORTABLE_FORMAT) {
        let portable: PortableExport = serde_json::from_value(root)
            .map_err(|e| format!("invalid portable JSON in {path:?}: {e}"))?;
        if portable.version != PORTABLE_VERSION {
            return Err(format!(
                "unsupported portable JSON version {} in {path:?}",
                portable.version
            ));
        }
        return portable
            .items
            .into_iter()
            .map(|mut item| {
                if item.name.trim().is_empty() {
                    return Err(format!("a portable JSON item in {path:?} has no name"));
                }
                if let Some(configuration) = item.totp.as_deref() {
                    let (normalized, _) =
                        normalize_totp_configuration(configuration).map_err(|error| {
                            format!("invalid TOTP configuration for {:?}: {error}", item.name)
                        })?;
                    item.totp = Some(normalized);
                }
                Ok(ImportedItem {
                    portable: true,
                    entry: VaultEntry {
                        id: 0,
                        name: item.name,
                        username: item.username,
                        password: item.password,
                        url: item.url,
                        notes: item.notes,
                        created: item.created,
                        modified: item.modified,
                    },
                    kind: item.kind,
                    additional_urls: item.additional_urls,
                    custom_fields: item.custom_fields,
                    password_changed: item.password_changed,
                    password_history: item.password_history,
                    totp: item.totp,
                })
            })
            .collect();
    }
    let bitwarden = root.get("items").is_some();
    let values = if let Some(items) = root.get("items").and_then(serde_json::Value::as_array) {
        items
    } else {
        root.as_array().ok_or_else(|| {
            "JSON import must be an array or a Bitwarden object with items".to_string()
        })?
    };
    let mut entries = Vec::new();
    for value in values {
        if bitwarden && value.get("type").and_then(serde_json::Value::as_u64) != Some(1) {
            continue;
        }
        let login = value.get("login").unwrap_or(value);
        let url = json_text(value, &["url", "website"]).or_else(|| {
            login
                .get("uris")
                .and_then(serde_json::Value::as_array)
                .and_then(|uris| uris.first())
                .and_then(|uri| json_text(uri, &["uri"]))
        });
        let name = json_text(value, &["name", "title"])
            .or_else(|| url.clone())
            .ok_or_else(|| format!("an imported JSON item in {path:?} has no name or URL"))?;
        let password = json_text(login, &["password"])
            .or_else(|| json_text(value, &["password"]))
            .ok_or_else(|| format!("an imported JSON item in {path:?} has no password"))?;
        let now = chrono::Local::now().to_string();
        entries.push(ImportedItem::login(VaultEntry {
            id: 0,
            name,
            username: json_text(login, &["username", "login"]),
            password,
            url,
            notes: json_text(value, &["notes", "note"]),
            created: json_text(value, &["created", "creationDate"]).unwrap_or_else(|| now.clone()),
            modified: json_text(value, &["modified", "revisionDate"]).unwrap_or(now),
        }));
    }
    if entries.is_empty() {
        return Err(format!("no supported login entries were found in {path:?}"));
    }
    Ok(entries)
}

impl Vault {
    const MAX_PASSWORD_HISTORY: usize = 10;

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

    #[allow(dead_code)]
    fn push_password_history(&mut self, entry_id: usize, password: String) {
        self.push_password_history_with_limit(entry_id, password, Self::MAX_PASSWORD_HISTORY);
    }

    fn metadata(&self, entry_id: usize) -> Option<&EntryMetadata> {
        self.recovery
            .entry_metadata
            .iter()
            .find(|record| record.entry_id == entry_id)
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
        if let PasswordType::Key(path) = &new_key
            && new_key_file_path(path)?.exists()
        {
            return Err("the new key file already exists".to_string());
        }
        let old_filename = self.metadata.filename.clone();
        if matches!(&new_key, PasswordType::Key(_)) {
            let mut key = try_gen_master_key(&mut new_key, true)?;
            key.zeroize();
        } else if find_vault(&mut new_key).is_some() {
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
        replacement.zeroize();
        if let Some(mut old_key) = server_info.keypass.replace(new_key) {
            old_key.zeroize();
        }
        Ok(())
    }

    pub async fn get_entry(&self, a: Target, stream: &mut TcpStream, http: bool) {
        self.get_entry_with_timeout(a, 15, stream, http).await;
    }

    pub async fn get_entry_with_timeout(
        &self,
        a: Target,
        copy_timeout: u8,
        stream: &mut TcpStream,
        http: bool,
    ) {
        match a {
            Target::Id(i) => {
                let Some(entry) = self.entries.iter().find(|entry| entry.id == i) else {
                    respond_with_code(ResponseCode::NotFound, "Invalid id.", stream, http).await;
                    return;
                };
                respond(&self.entry_details(entry), stream, http).await;
                if !entry.password.is_empty() {
                    copy_in_background(entry.password.clone(), copy_timeout);
                }
            }
            Target::Name(name) => {
                if let Some(entry) = self.entries.iter().find(|entry| entry.name == name) {
                    respond(&self.entry_details(entry), stream, http).await;
                    if !entry.password.is_empty() {
                        copy_in_background(entry.password.clone(), copy_timeout);
                    }
                } else {
                    respond_with_code(ResponseCode::NotFound, "Not found.\n", stream, http).await;
                }
            }
            Target::Url(u) => {
                if let Some(json) = url_match_json(
                    &self.entries,
                    &self.recovery.totp,
                    &self.recovery.entry_metadata,
                    &u,
                ) {
                    respond(&json, stream, http).await;
                } else {
                    respond_with_code(ResponseCode::NotFound, "Not found.\n", stream, http).await;
                }
            }
            Target::Vault { .. } => {
                respond_with_code(
                    ResponseCode::InvalidInput,
                    "Invalid entry selector.",
                    stream,
                    http,
                )
                .await
            }
        }
    }

    pub async fn get_secret(&self, target: Target, stream: &mut TcpStream, http: bool) {
        let entry = match target {
            Target::Id(id) => self.entries.iter().find(|entry| entry.id == id),
            Target::Name(name) => self.entries.iter().find(|entry| entry.name == name),
            Target::Url(_) | Target::Vault { .. } => None,
        };
        if let Some(entry) = entry {
            respond(&entry.password, stream, http).await;
        } else {
            respond_with_code(ResponseCode::NotFound, "Not found.\n", stream, http).await;
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

        let mut recovery_before = self.recovery.clone();
        let mut removed = self.entries.remove(index);
        let removed_id = removed.id;
        let mut history = Vec::new();
        for revision in std::mem::take(&mut self.recovery.password_history) {
            if revision.entry_id == removed_id {
                history.push(revision);
            } else {
                self.recovery.password_history.push(revision);
            }
        }
        self.recovery.trash.push(TrashedEntry {
            entry: removed.clone(),
            history,
            deleted: chrono::Local::now().to_string(),
        });
        if let Err(error) = write_vault(self, key_pass) {
            self.entries.insert(index, removed);
            self.recovery.zeroize();
            self.recovery = recovery_before;
            return Err(error);
        }
        removed.zeroize();
        recovery_before.zeroize();
        Ok(true)
    }

    #[allow(dead_code)]
    pub fn update_entry(
        &mut self,
        change: EntryUpdate,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        self.update_entry_with_limit(change, key_pass, Self::MAX_PASSWORD_HISTORY)
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

    #[allow(dead_code)]
    pub fn update_typed_entry(
        &mut self,
        change: TypedUpdate,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        self.update_typed_entry_with_limit(change, key_pass, Self::MAX_PASSWORD_HISTORY)
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
        let mut recovery_before = self.recovery.clone();
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
            self.recovery.zeroize();
            self.recovery = recovery_before;
            return Err(error);
        }
        original.zeroize();
        recovery_before.zeroize();
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
        let mut recovery_before = self.recovery.clone();
        let mut modified_before = self.entries[entry_index].modified.clone();

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
            self.recovery.zeroize();
            self.recovery = recovery_before;
            return Err(error);
        }
        modified_before.zeroize();
        recovery_before.zeroize();
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
        let mut recovery_before = self.recovery.clone();
        let mut modified_before = self.entries[entry_index].modified.clone();
        let mut removed = self.recovery.totp.remove(record_index);
        removed.zeroize();
        self.entries[entry_index].modified = chrono::Local::now().to_string();

        if let Err(error) = write_vault(self, key_pass) {
            self.entries[entry_index].modified.zeroize();
            self.entries[entry_index].modified = modified_before;
            self.recovery.zeroize();
            self.recovery = std::mem::take(&mut recovery_before);
            return Err(error);
        }
        modified_before.zeroize();
        recovery_before.zeroize();
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

    pub async fn view_password_history(&self, target: Target, stream: &mut TcpStream, http: bool) {
        let Some(index) = self.entry_index(&target) else {
            respond_with_code(ResponseCode::NotFound, "Entry not found.", stream, http).await;
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
            respond("No password history.", stream, http).await;
            return;
        }
        for (index, revision) in revisions.iter().enumerate() {
            respond(
                &format!("{}. changed {}\n", index + 1, revision.changed),
                stream,
                http,
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
        let mut entries_before = self.entries.clone();
        let mut recovery_before = self.recovery.clone();
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
            self.entries.zeroize();
            self.entries = std::mem::take(&mut entries_before);
            self.recovery.zeroize();
            self.recovery = std::mem::take(&mut recovery_before);
            return Err(error);
        }
        entries_before.zeroize();
        recovery_before.zeroize();
        Ok(true)
    }

    pub async fn view_trash(&self, stream: &mut TcpStream, http: bool) {
        if self.recovery.trash.is_empty() {
            respond("Trash is empty.", stream, http).await;
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
                http,
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
        let mut recovery_before = self.recovery.clone();
        let mut trashed = self.recovery.trash.remove(index);
        if self.entries.iter().any(|entry| {
            entry.name == trashed.entry.name && entry.username == trashed.entry.username
        }) {
            self.recovery.zeroize();
            self.recovery = std::mem::take(&mut recovery_before);
            trashed.zeroize();
            return Err(
                "an active entry with the same name and username already exists".to_string(),
            );
        }
        let restored_id = trashed.entry.id;
        if self.entries.iter().any(|entry| entry.id == restored_id) {
            self.recovery.zeroize();
            self.recovery = std::mem::take(&mut recovery_before);
            trashed.zeroize();
            return Err("an active entry already uses this stable ID".to_string());
        }
        for revision in &mut trashed.history {
            revision.entry_id = restored_id;
        }
        self.recovery.password_history.append(&mut trashed.history);
        self.entries.push(trashed.entry);
        if let Err(error) = write_vault(self, key_pass) {
            self.entries.pop().zeroize();
            self.recovery.zeroize();
            self.recovery = std::mem::take(&mut recovery_before);
            return Err(error);
        }
        recovery_before.zeroize();
        Ok(true)
    }

    pub fn purge_trash(
        &mut self,
        trash_id: Option<usize>,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        let mut recovery_before = self.recovery.clone();
        let changed = if let Some(id) = trash_id {
            let Some(index) = id
                .checked_sub(1)
                .filter(|index| *index < self.recovery.trash.len())
            else {
                return Ok(false);
            };
            let mut removed = self.recovery.trash.remove(index);
            let removed_id = removed.entry.id;
            removed.zeroize();
            self.remove_totp_records(&[removed_id]);
            self.remove_metadata_records(&[removed_id]);
            true
        } else {
            let changed = !self.recovery.trash.is_empty();
            let removed_ids = self
                .recovery
                .trash
                .iter()
                .map(|trashed| trashed.entry.id)
                .collect::<Vec<_>>();
            self.recovery.trash.zeroize();
            self.remove_totp_records(&removed_ids);
            self.remove_metadata_records(&removed_ids);
            changed
        };
        if changed && let Err(error) = write_vault(self, key_pass) {
            self.recovery.zeroize();
            self.recovery = std::mem::take(&mut recovery_before);
            return Err(error);
        }
        recovery_before.zeroize();
        Ok(changed)
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
        let mut recovery_before = self.recovery.clone();
        let mut retained = Vec::with_capacity(self.recovery.trash.len() - removed_ids.len());
        for mut item in std::mem::take(&mut self.recovery.trash) {
            if removed_ids.contains(&item.entry.id) {
                item.zeroize();
            } else {
                retained.push(item);
            }
        }
        self.recovery.trash = retained;
        self.remove_totp_records(&removed_ids);
        self.remove_metadata_records(&removed_ids);
        if let Err(error) = write_vault(self, key_pass) {
            self.recovery.zeroize();
            self.recovery = std::mem::take(&mut recovery_before);
            return Err(error);
        }
        recovery_before.zeroize();
        Ok(removed_ids.len())
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

    fn audit_report(
        &self,
        options: &AuditOptions,
        breached: Option<&HashMap<String, u64>>,
        breach_error: Option<&str>,
    ) -> String {
        let mut weak = Vec::new();
        let mut stale = Vec::new();
        let mut missing_totp = Vec::new();
        let mut breached_entries = Vec::new();
        let mut passwords: HashMap<&str, Vec<&VaultEntry>> = HashMap::new();
        let mut identities: HashMap<(String, String), Vec<&VaultEntry>> = HashMap::new();
        let logins = self
            .entries
            .iter()
            .filter(|entry| self.item_kind(entry.id) == ItemKind::Login)
            .collect::<Vec<_>>();
        let mut unhealthy = HashSet::new();
        for &entry in &logins {
            if zxcvbn::zxcvbn(&entry.password, &[]).score() <= zxcvbn::Score::Two {
                weak.push(entry);
                unhealthy.insert(entry.id);
            }
            if options
                .stale_days
                .is_some_and(|days| self.password_is_stale(entry, days))
            {
                stale.push(entry);
                unhealthy.insert(entry.id);
            }
            if options.require_totp
                && !self
                    .recovery
                    .totp
                    .iter()
                    .any(|record| record.entry_id == entry.id)
            {
                missing_totp.push(entry);
                unhealthy.insert(entry.id);
            }
            if let Some(count) = breached
                .and_then(|hashes| hashes.get(&password_hash(&entry.password)))
                .copied()
            {
                breached_entries.push((entry, count));
                unhealthy.insert(entry.id);
            }
            passwords.entry(&entry.password).or_default().push(entry);
            let identity = (
                entry
                    .url
                    .as_deref()
                    .and_then(hostname)
                    .unwrap_or_else(|| entry.name.to_ascii_lowercase()),
                entry.username.as_deref().unwrap_or("").to_ascii_lowercase(),
            );
            identities.entry(identity).or_default().push(entry);
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
        let healthy = logins.len().saturating_sub(unhealthy.len());
        let score = if logins.is_empty() {
            100
        } else {
            healthy * 100 / logins.len()
        };
        let mut report = format!(
            "Health score: {score}/100 ({healthy}/{} login entries have no detected issues).\nAudit: {} weak entries, {} reused-password groups, {} duplicate-login groups, {} stale entries, {} missing TOTP, {} breached entries.\n",
            logins.len(),
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
                entry.id,
                entry.name,
                self.password_changed(entry)
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

    pub async fn audit(&self, options: AuditOptions, stream: &mut TcpStream, http: bool) {
        let breach_result = if options.check_breaches {
            Some(
                breached_hashes(
                    self.entries
                        .iter()
                        .filter(|entry| self.item_kind(entry.id) == ItemKind::Login)
                        .map(|entry| entry.password.as_str()),
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
        respond_with_code(
            code,
            &self.audit_report(&options, breached, error),
            stream,
            http,
        )
        .await;
    }

    fn is_weak(&self, entry: &VaultEntry) -> bool {
        !entry.password.is_empty()
            && zxcvbn::zxcvbn(&entry.password, &[]).score() <= zxcvbn::Score::Two
    }

    fn apply_list_options<'a>(
        &'a self,
        mut entries: Vec<&'a VaultEntry>,
        options: &ListOptions,
    ) -> Vec<&'a VaultEntry> {
        entries.retain(|entry| {
            options
                .kind
                .is_none_or(|kind| self.item_kind(entry.id) == kind)
                && options.has_totp.is_none_or(|expected| {
                    self.recovery
                        .totp
                        .iter()
                        .any(|record| record.entry_id == entry.id)
                        == expected
                })
                && (!options.weak || self.is_weak(entry))
                && options
                    .stale_days
                    .is_none_or(|days| self.password_is_stale(entry, days))
        });
        entries.sort_by(|left, right| {
            let ordering = match options.sort {
                SortField::Id => left.id.cmp(&right.id),
                SortField::Name => left.name.to_lowercase().cmp(&right.name.to_lowercase()),
                SortField::Created => left.created.cmp(&right.created),
                SortField::Modified => left.modified.cmp(&right.modified),
                SortField::PasswordAge => self
                    .password_changed(left)
                    .cmp(self.password_changed(right)),
            };
            if options.descending {
                ordering.reverse()
            } else {
                ordering
            }
        });
        entries
    }

    fn entry_summary(&self, entry: &VaultEntry) -> String {
        let totp = self.totp_marker(entry.id);
        let urls = self.all_urls(entry).collect::<Vec<_>>().join(", ");
        let fields = self
            .custom_fields(entry.id)
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
            self.item_kind(entry.id),
            entry.username,
            (!urls.is_empty()).then_some(urls),
            entry.notes,
            fields,
            totp
        )
    }

    pub async fn view_entries(&self, options: ListOptions, stream: &mut TcpStream, http: bool) {
        if self.entries.is_empty() {
            respond("No entries.", stream, http).await;
            return;
        }
        let entries = self.apply_list_options(self.entries.iter().collect(), &options);
        if entries.is_empty() {
            respond_with_code(ResponseCode::NotFound, "No matching entries.", stream, http).await;
            return;
        }
        for entry in entries {
            respond(&self.entry_summary(entry), stream, http).await;
        }
    }

    fn browser_autofill_json(&self) -> String {
        let items = self
            .entries
            .iter()
            .filter_map(|entry| {
                let kind = self.item_kind(entry.id);
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

    pub async fn browser_autofill(&self, stream: &mut TcpStream, http: bool) {
        respond(&self.browser_autofill_json(), stream, http).await;
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

    pub async fn browser_autofill_item(&self, id: usize, stream: &mut TcpStream, http: bool) {
        if let Some(item) = self.browser_autofill_item_json(id) {
            respond(&item, stream, http).await;
        } else {
            respond_with_code(
                ResponseCode::NotFound,
                "Autofill item not found.",
                stream,
                http,
            )
            .await;
        }
    }

    fn search_entries(&self, filter: &SearchFilter) -> Vec<&VaultEntry> {
        fn field_matches(value: Option<&str>, needle: Option<&str>) -> bool {
            needle.is_none_or(|needle| {
                value.is_some_and(|value| value.to_lowercase().contains(&needle.to_lowercase()))
            })
        }

        let query = filter.query.as_ref().map(|query| query.to_lowercase());
        self.entries
            .iter()
            .filter(|entry| {
                let query_matches = query.as_ref().is_none_or(|query| {
                    entry.name.to_lowercase().contains(query)
                        || entry
                            .username
                            .as_deref()
                            .is_some_and(|value| value.to_lowercase().contains(query))
                        || self
                            .all_urls(entry)
                            .any(|value| value.to_lowercase().contains(query))
                        || entry
                            .notes
                            .as_deref()
                            .is_some_and(|value| value.to_lowercase().contains(query))
                        || self.custom_fields(entry.id).iter().any(|field| {
                            field.name.to_lowercase().contains(query)
                                || (!field.secret && field.value.to_lowercase().contains(query))
                        })
                });
                query_matches
                    && field_matches(Some(&entry.name), filter.name.as_deref())
                    && field_matches(entry.username.as_deref(), filter.username.as_deref())
                    && filter.url.as_ref().is_none_or(|needle| {
                        let needle = needle.to_lowercase();
                        self.all_urls(entry)
                            .any(|url| url.to_lowercase().contains(&needle))
                    })
                    && field_matches(entry.notes.as_deref(), filter.notes.as_deref())
            })
            .collect()
    }

    pub async fn search(&self, filter: SearchFilter, stream: &mut TcpStream, http: bool) {
        let entries = self.apply_list_options(self.search_entries(&filter), &filter.list);
        if entries.is_empty() {
            respond_with_code(ResponseCode::NotFound, "No matching entries.", stream, http).await;
            return;
        }
        for entry in entries {
            respond(&self.entry_summary(entry), stream, http).await;
        }
    }

    pub fn lock_vault(&self, key_pass: &mut ServerInfo) -> Result<(), String> {
        write_vault(self, key_pass)?;
        key_pass.zeroize();
        Ok(())
    }
    pub fn export(&self, path: String) -> Result<(), String> {
        if std::path::Path::new(&path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        {
            let items = self
                .entries
                .iter()
                .map(|entry| {
                    let metadata = self.metadata(entry.id);
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
                        password_history: self
                            .recovery
                            .password_history
                            .iter()
                            .filter(|revision| revision.entry_id == entry.id)
                            .map(|revision| PortableRevision {
                                password: revision.password.clone(),
                                changed: revision.changed.clone(),
                            })
                            .collect(),
                        totp: self
                            .recovery
                            .totp
                            .iter()
                            .find(|record| record.entry_id == entry.id)
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
            let result = persist_private_file(Path::new(&path), &encoded, true)
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
        let result = persist_private_file(Path::new(&path), &encoded, true)
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
        let mut plaintext = rmp_serde::to_vec(&envelope)
            .map_err(|error| format!("could not encode backup: {error}"))?;
        let encrypted = try_encrypt_file(key_pass, &plaintext);
        plaintext.zeroize();
        let mut encrypted = encrypted?;
        let mut output = Vec::with_capacity(BACKUP_MAGIC.len() + 1 + encrypted.len());
        output.extend_from_slice(BACKUP_MAGIC);
        output.push(BACKUP_VERSION);
        output.extend_from_slice(&encrypted);
        encrypted.zeroize();
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
        let contents = Zeroizing::new(
            fs::read_to_string(&path)
                .map_err(|e| format!("could not open import file {path:?}: {e}"))?,
        );
        let trimmed = contents.trim_start();
        let imported = if trimmed.starts_with('{') || trimmed.starts_with('[') {
            import_json(&contents, &path)?
        } else {
            import_csv(&contents, &path)?
        };
        let mut report = ImportReport {
            total: imported.len(),
            preview,
            ..ImportReport::default()
        };
        let mut entries_before = self.entries.clone();
        let mut recovery_before = self.recovery.clone();
        for mut imported in imported {
            let duplicate = self.entries.iter().position(|existing| {
                existing.name == imported.entry.name
                    && existing.username == imported.entry.username
                    && existing.url == imported.entry.url
            });
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
                            if !self.entries.iter().any(|existing| {
                                existing.name == candidate
                                    && existing.username == imported.entry.username
                            }) {
                                imported.entry.name = candidate;
                                break;
                            }
                            suffix += 1;
                        }
                        let id = self.allocate_entry_id()?;
                        imported.entry.id = id;
                        self.entries.push(std::mem::take(&mut imported.entry));
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

    #[allow(dead_code)]
    pub fn import(&mut self, path: String) -> Result<(), String> {
        self.import_with_options(
            path,
            ConflictPolicy::Skip,
            false,
            Self::MAX_PASSWORD_HISTORY,
            &mut ServerInfo::default(),
        )
        .map(|_| ())
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

#[allow(dead_code)]
pub trait VaultAccess {
    async fn get_entry(&self, a: Target, stream: &mut TcpStream, http: bool);
    async fn get_secret(&self, target: Target, stream: &mut TcpStream, http: bool);
    fn add_entry(&mut self, info: PasswordEntry, key_pass: &mut ServerInfo)
    -> Result<bool, String>;
    fn add_typed_entry(
        &mut self,
        info: TypedEntry,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String>;
    fn delete_entry(&mut self, id: Target, key_pass: &mut ServerInfo) -> Result<bool, String>;
    fn update_entry(&mut self, add: EntryUpdate, key_pass: &mut ServerInfo)
    -> Result<bool, String>;
    fn update_entry_with_limit(
        &mut self,
        update: EntryUpdate,
        key_pass: &mut ServerInfo,
        password_history_limit: usize,
    ) -> Result<bool, String>;
    fn update_typed_entry(
        &mut self,
        update: TypedUpdate,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String>;
    fn update_typed_entry_with_limit(
        &mut self,
        update: TypedUpdate,
        key_pass: &mut ServerInfo,
        password_history_limit: usize,
    ) -> Result<bool, String>;
    async fn view_entries(&self, options: ListOptions, stream: &mut TcpStream, http: bool);
    fn lock_vault(&self, key_pass: &mut ServerInfo) -> Result<(), String>;
    fn unlock_vault(&mut self, key_pass: &mut ServerInfo) -> Result<(), String>;
    fn export(&self, path: String) -> Result<(), String>;
    fn import(&mut self, path: String) -> Result<(), String>;
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
    async fn get_entry(&self, a: Target, stream: &mut TcpStream, http: bool) {
        if let Some(vlt) = self {
            vlt.get_entry(a, stream, http).await
        }
    }
    async fn get_secret(&self, target: Target, stream: &mut TcpStream, http: bool) {
        if let Some(vault) = self {
            vault.get_secret(target, stream, http).await;
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

    fn update_entry(
        &mut self,
        add: EntryUpdate,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        match self {
            Some(vlt) => vlt.update_entry(add, key_pass),
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
    fn update_typed_entry(
        &mut self,
        update: TypedUpdate,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, String> {
        match self {
            Some(vlt) => vlt.update_typed_entry(update, key_pass),
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
    async fn view_entries(&self, options: ListOptions, stream: &mut TcpStream, http: bool) {
        if let Some(vlt) = self {
            vlt.view_entries(options, stream, http).await;
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
    fn export(&self, path: String) -> Result<(), String> {
        if let Some(vlt) = self {
            vlt.export(path)
        } else {
            Err("vault is locked".to_string())
        }
    }
    fn import(&mut self, path: String) -> Result<(), String> {
        if let Some(vlt) = self {
            vlt.import(path)
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
    if let PasswordType::Key(key_path) = &key
        && !key_file_path(key_path)?.is_file()
    {
        return Err("key file does not exist or is not a regular file".to_string());
    }
    let (filename, mut vault, _) = find_vault(&mut key)
        .ok_or_else(|| "could not delete vault (is the key correct?)".to_string())?;
    vault.zeroize();
    fs::remove_file(data.join(filename))
        .map_err(|e| format!("could not delete vault (is the key correct?): {e}"))?;
    if let PasswordType::Key(key) = key
        && !keep_key
    {
        fs::remove_file(key_file_path(&key)?)
            .map_err(|e| format!("vault deleted, but could not delete its key file: {e}"))?;
    }
    Ok(())
}
#[cfg(test)]
mod test {
    #![allow(unused_must_use)]
    use super::*;
    use crate::encryption::gen_master_key;
    use crate::file::init_test_data_dir;
    use chrono::FixedOffset;
    use std::{fs, thread};

    fn time_close(time: String) -> bool {
        let thing =
            chrono::DateTime::<FixedOffset>::parse_from_str(&time, "%Y-%m-%d %H:%M:%S%.f %:z")
                .unwrap();
        let diff = chrono::Local::now().signed_duration_since(thing);
        diff.num_seconds() < 1
    }

    #[test]
    fn renamed_entries_field_preserves_compact_vault_format() {
        #[derive(Serialize)]
        struct LegacyVault {
            enteries: Vec<VaultEntry>,
            metadata: VaultMetadata,
        }

        let legacy = LegacyVault {
            enteries: vec![VaultEntry {
                id: 1,
                name: "example".to_string(),
                password: "secret".to_string(),
                ..VaultEntry::default()
            }],
            metadata: VaultMetadata {
                filename: "legacy.enc".to_string(),
            },
        };
        let encoded = rmp_serde::to_vec(&legacy).unwrap();
        let decoded: Vault = rmp_serde::from_slice(&encoded).unwrap();

        assert_eq!(decoded.entries[0].name, "example");
        assert_eq!(decoded.metadata.filename, "legacy.enc");
    }

    #[test]
    fn test_url_match_json_escapes_special_chars() {
        let entries = vec![VaultEntry {
            id: 1,
            name: String::from("site\"with\"quote"),
            username: Some(String::from("bob")),
            password: String::from("pa\"ss\\wrd"),
            url: Some(String::from("example.com")),
            notes: None,
            created: String::from("2026-01-01"),
            modified: String::from("2026-01-01"),
        }];
        let totp = vec![TotpRecord {
            entry_id: 1,
            configuration: "secret-never-exported".into(),
        }];
        let json = url_match_json(&entries, &totp, &[], "example.com").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["password"], "pa\"ss\\wrd");
        assert_eq!(parsed[0]["name"], "site\"with\"quote");
        assert_eq!(parsed[0]["username"], "bob");
        assert_eq!(parsed[0]["id"], 1);
        assert_eq!(parsed[0]["has_totp"], true);
        assert!(!json.contains("secret-never-exported"));
    }
    #[test]
    fn test_url_match_json_no_match_returns_none() {
        let entries = vec![VaultEntry {
            id: 1,
            name: String::from("x"),
            username: None,
            password: String::from("p"),
            url: Some(String::from("other.com")),
            notes: None,
            created: String::from("2026-01-01"),
            modified: String::from("2026-01-01"),
        }];
        assert!(url_match_json(&entries, &[], &[], "example.com").is_none());
    }

    #[test]
    fn browser_autofill_returns_only_cards_and_identities() {
        let mut vault = recovery_test_vault(vec![
            recovery_test_entry(1, "login", "login-user", "login-password"),
            recovery_test_entry(2, "Personal Visa", "Alice Example", "4111111111111111"),
            recovery_test_entry(3, "Home identity", "alice@example.com", ""),
        ]);
        vault.recovery.entry_metadata = vec![
            EntryMetadata {
                entry_id: 2,
                kind: ItemKind::PaymentCard,
                custom_fields: vec![CustomField {
                    name: "expiration month".into(),
                    value: "09".into(),
                    secret: false,
                }],
                ..EntryMetadata::default()
            },
            EntryMetadata {
                entry_id: 3,
                kind: ItemKind::Identity,
                custom_fields: vec![CustomField {
                    name: "city".into(),
                    value: "Boise".into(),
                    secret: false,
                }],
                ..EntryMetadata::default()
            },
        ];

        let parsed: serde_json::Value =
            serde_json::from_str(&vault.browser_autofill_json()).unwrap();
        let items = parsed.as_array().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0]["kind"], "payment-card");
        assert!(items[0].get("primary_secret").is_none());
        assert!(items[0].get("custom_fields").is_none());
        assert_eq!(items[1]["kind"], "identity");
        assert!(!vault.browser_autofill_json().contains("login-password"));

        let card: serde_json::Value =
            serde_json::from_str(&vault.browser_autofill_item_json(2).unwrap()).unwrap();
        assert_eq!(card["primary_secret"], "4111111111111111");
        assert_eq!(card["custom_fields"][0]["value"], "09");
        assert!(vault.browser_autofill_item_json(1).is_none());
    }

    #[test]
    fn test_url_match_json_rejects_substring_lookalike() {
        let entries = vec![VaultEntry {
            id: 1,
            name: String::from("lookalike"),
            username: Some(String::from("alice")),
            password: String::from("secret"),
            url: Some(String::from("https://notexample.com/login")),
            notes: None,
            created: String::from("2026-01-01"),
            modified: String::from("2026-01-01"),
        }];
        assert!(url_match_json(&entries, &[], &[], "example.com").is_none());
    }

    #[test]
    fn test_hostname_ignores_scheme_path_port_and_case() {
        assert!(hosts_match("HTTPS://Example.COM:443/login", "example.com"));
    }
    #[test]
    fn https_credentials_are_not_returned_to_http_pages() {
        assert!(!hosts_match(
            "https://example.com/login",
            "http://example.com"
        ));
        assert!(hosts_match(
            "https://example.com/login",
            "https://example.com"
        ));
        assert!(!hosts_match("example.com", "http://example.com"));
        assert!(hosts_match("http://example.com", "https://example.com"));
    }
    #[test]
    fn test_domain_matching_is_exact_by_default() {
        assert!(!hosts_match("example.com", "login.example.com"));
        assert!(!hosts_match("mail.example.com", "example.com"));
    }
    #[test]
    fn test_explicit_wildcard_matches_only_subdomains() {
        assert!(hosts_match("*.example.com", "login.example.com"));
        assert!(!hosts_match("*.example.com", "example.com"));
        assert!(!hosts_match("*.github.io", "attacker.github.io"));
    }
    #[test]
    fn test_url_match_json_partial_match() {
        let entries = vec![VaultEntry {
            id: 2,
            name: String::from("x"),
            username: None,
            password: String::from("p"),
            url: Some(String::from("*.example.com")),
            notes: None,
            created: String::from("2026-01-01"),
            modified: String::from("2026-01-01"),
        }];
        let json = url_match_json(&entries, &[], &[], "mail.example.com").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed[0]["id"], 2);
        assert_eq!(parsed[0]["has_totp"], false);
    }
    #[test]
    fn test_add_entry_returns_false_for_duplicate() {
        let mut vlt = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        let entry = PasswordEntry {
            name: String::from("test"),
            username: Some(String::from("user1")),
            password: String::from("pass1"),
            url: None,
            notes: None,
            copy: false,
        };
        let mut si = ServerInfo {
            locked: true,
            keypass: None,
        };
        assert!(vlt.add_entry(entry.clone(), &mut si).unwrap());
        assert!(!vlt.add_entry(entry, &mut si).unwrap());
    }
    #[test]
    fn test_delete_entry_returns_false_when_not_found() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: None,
                password: String::from("p"),
                url: None,
                notes: None,
                created: String::from("2026-01-01"),
                modified: String::from("2026-01-01"),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        let mut si = ServerInfo {
            locked: true,
            keypass: None,
        };
        assert!(
            !vlt.delete_entry(Target::Name("nope".into()), &mut si)
                .unwrap()
        );
        assert!(
            vlt.delete_entry(Target::Name("test".into()), &mut si)
                .unwrap()
        );
    }
    #[test]
    fn test_update_entry_returns_false_when_not_found() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: None,
                password: String::from("p"),
                url: None,
                notes: None,
                created: String::from("2026-01-01"),
                modified: String::from("2026-01-01"),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        let mut si = ServerInfo {
            locked: true,
            keypass: None,
        };
        let upd = EntryUpdate {
            target: Target::Name("nope".into()),
            update: UpdateArgs {
                name: Some("x".into()),
                username: None,
                password: false,
                generate_password: false,
                url: None,
                notes: None,
            },
            password: None,
        };
        assert!(!vlt.update_entry(upd, &mut si).unwrap());
    }
    #[test]
    fn test_add_entry() {
        let mut vault: Vault = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vault.add_entry(
            PasswordEntry {
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                copy: false,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        let expected = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: vault.entries[0].created.clone(),
                modified: vault.entries[0].modified.clone(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData {
                next_entry_id: 2,
                ..RecoveryData::default()
            },
        };
        assert_eq!(vault, expected);
        assert!(time_close(vault.entries[0].created.clone()));
        assert!(time_close(vault.entries[0].modified.clone()));
    }
    #[test]
    fn test_delete_id() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt.delete_entry(
            Target::Id(1),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert!(vlt.entries.is_empty());
        assert_eq!(vlt.recovery.trash.len(), 1);
        assert_eq!(vlt.recovery.trash[0].entry.name, "test");
    }
    #[test]
    fn test_delete_name() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt.delete_entry(
            Target::Name("test".into()),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert!(vlt.entries.is_empty());
        assert_eq!(vlt.recovery.trash.len(), 1);
        assert_eq!(vlt.recovery.trash[0].entry.name, "test");
    }
    #[test]
    fn test_update_id() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt.update_entry(
            EntryUpdate {
                target: Target::Id(1),
                update: UpdateArgs {
                    name: Some(String::from("test2")),
                    username: Some(String::from("test2")),
                    password: false,
                    generate_password: false,
                    url: None,
                    notes: None,
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        let expected = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test2"),
                username: Some(String::from("test2")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: vlt.entries[0].created.clone(),
                modified: vlt.entries[0].modified.clone(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        assert_eq!(vlt, expected);
        assert!(time_close(vlt.entries[0].modified.clone()))
    }
    #[test]
    fn test_update_name() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt.update_entry(
            EntryUpdate {
                target: Target::Name(String::from("test")),
                update: UpdateArgs {
                    name: Some(String::from("test2")),
                    username: Some(String::from("test2")),
                    password: false,
                    generate_password: false,
                    url: None,
                    notes: None,
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        let expected = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test2"),
                username: Some(String::from("test2")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: vlt.entries[0].created.clone(),
                modified: vlt.entries[0].modified.clone(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        assert_eq!(vlt, expected);
        assert!(time_close(vlt.entries[0].modified.clone()))
    }
    #[test]
    fn test_export_import() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("export.csv");

        let vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData {
                next_entry_id: 2,
                ..RecoveryData::default()
            },
        };
        vlt.export(path.display().to_string()).unwrap();
        let mut vlt1 = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt1.import(path.display().to_string()).unwrap();
        assert_eq!(vlt, vlt1);
    }

    #[test]
    fn test_failed_import_does_not_partially_modify_vault() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "id,name,username,password,url,notes,created,modified").unwrap();
        writeln!(file, "2,valid,user,password,,,created,modified").unwrap();
        writeln!(file, "not-an-id,invalid,user,,,,created,modified").unwrap();

        let mut vault = Vault::default();
        assert!(vault.import(file.path().display().to_string()).is_err());
        assert!(vault.entries.is_empty());
    }

    #[test]
    fn test_imports_chrome_style_csv() {
        let csv =
            "name,url,username,password,note\nExample,https://example.com,alice,secret,personal\n";
        let entries = import_csv(csv, "chrome.csv").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry.name, "Example");
        assert_eq!(entries[0].entry.username.as_deref(), Some("alice"));
        assert_eq!(entries[0].entry.notes.as_deref(), Some("personal"));
    }

    #[test]
    fn test_imports_bitwarden_json() {
        let json = r#"{
            "items": [{
                "type": 1,
                "name": "Example",
                "notes": "work",
                "login": {
                    "username": "alice",
                    "password": "secret",
                    "uris": [{"uri": "https://example.com/login"}]
                }
            }]
        }"#;
        let entries = import_json(json, "bitwarden.json").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry.username.as_deref(), Some("alice"));
        assert_eq!(
            entries[0].entry.url.as_deref(),
            Some("https://example.com/login")
        );
    }

    #[test]
    fn test_json_export_round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("export.json");
        let vault = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: "Example".into(),
                username: Some("alice".into()),
                password: "secret".into(),
                url: Some("example.com".into()),
                notes: None,
                created: "created".into(),
                modified: "modified".into(),
            }],
            metadata: VaultMetadata::default(),
            recovery: RecoveryData {
                password_history: vec![PasswordRevision {
                    entry_id: 1,
                    password: "previous-secret".into(),
                    changed: "2025-01-01T00:00:00Z".into(),
                }],
                totp: vec![TotpRecord {
                    entry_id: 1,
                    configuration: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into(),
                }],
                entry_metadata: vec![EntryMetadata {
                    entry_id: 1,
                    kind: ItemKind::ApiSecret,
                    additional_urls: vec!["api.example.com".into()],
                    password_changed: Some("2026-01-01T00:00:00Z".into()),
                    custom_fields: vec![CustomField {
                        name: "environment".into(),
                        value: "production".into(),
                        secret: false,
                    }],
                }],
                ..RecoveryData::default()
            },
        };
        vault.export(path.display().to_string()).unwrap();
        let exported: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(exported["format"], PORTABLE_FORMAT);
        assert_eq!(exported["version"], PORTABLE_VERSION);
        let mut imported = Vault::default();
        imported.import(path.display().to_string()).unwrap();
        assert_eq!(imported.entries, vault.entries);
        assert_eq!(
            imported.recovery.entry_metadata,
            vault.recovery.entry_metadata
        );
        assert_eq!(
            imported.recovery.password_history,
            vault.recovery.password_history
        );
        assert_eq!(imported.recovery.totp, vault.recovery.totp);
    }

    #[test]
    fn test_import_assigns_local_stable_ids() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "id,name,username,password,url,notes,created,modified").unwrap();
        writeln!(file, "99,first,user,password,,,created,modified").unwrap();

        let mut vault = Vault::default();
        vault.import(file.path().display().to_string()).unwrap();
        assert_eq!(vault.entries[0].id, 1);
    }

    #[test]
    fn portable_import_remaps_ids_for_associated_records() {
        let file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        let portable = serde_json::json!({
            "format": PORTABLE_FORMAT,
            "version": PORTABLE_VERSION,
            "exported_at": "2026-01-01T00:00:00Z",
            "items": [{
                "id": 999,
                "name": "Imported API",
                "username": "alice",
                "password": "current-secret",
                "url": "https://api.example.com",
                "notes": null,
                "created": "2025-01-01T00:00:00Z",
                "modified": "2026-01-01T00:00:00Z",
                "type": "api-secret",
                "additional_urls": ["https://backup.example.com"],
                "custom_fields": [{"name": "env", "value": "prod", "secret": false}],
                "password_changed": "2026-01-01T00:00:00Z",
                "password_history": [{"password": "old-secret", "changed": "2025-06-01T00:00:00Z"}],
                "totp": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
            }]
        });
        fs::write(file.path(), serde_json::to_vec(&portable).unwrap()).unwrap();

        let mut vault = recovery_test_vault(vec![recovery_test_entry(
            10,
            "Existing",
            "bob",
            "existing-secret",
        )]);
        vault.import(file.path().display().to_string()).unwrap();

        assert_eq!(vault.entries[1].id, 11);
        assert_eq!(vault.recovery.entry_metadata[0].entry_id, 11);
        assert_eq!(vault.recovery.password_history[0].entry_id, 11);
        assert_eq!(vault.recovery.totp[0].entry_id, 11);
    }

    #[test]
    fn test_import_new_persists_vault_to_disk() {
        init_test_data_dir();
        let pass = PasswordType::Password("import_fix_test_pass!".to_string());
        let mut server_info = ServerInfo {
            locked: true,
            keypass: Some(pass.clone()),
        };
        let mut vlt: Option<Vault> = None;
        create_vault(&mut vlt, &mut server_info, false).unwrap();

        let mut tf = NamedTempFile::new().unwrap();
        {
            use std::io::Write;
            writeln!(tf, "id,name,username,password,url,notes,created,modified").unwrap();
            writeln!(
                tf,
                "1,example.com,bob,secret,,,2026-01-01 00:00:00,2026-01-01 00:00:00"
            )
            .unwrap();
            writeln!(
                tf,
                "2,test.org,alice,pw456,,,2026-01-02 00:00:00,2026-01-02 00:00:00"
            )
            .unwrap();
        }
        vlt.import(tf.path().to_str().unwrap().to_string()).unwrap();

        vlt.lock_vault(&mut server_info);

        let vlt1 = unlock_vault(&mut ServerInfo {
            locked: true,
            keypass: Some(pass),
        })
        .unwrap();
        assert_eq!(vlt1.entries.len(), 2);
        assert_eq!(vlt1.entries[0].name, "example.com");
        assert_eq!(vlt1.entries[1].name, "test.org");

        let fname = vlt1.metadata.filename.clone();
        let _ = fs::remove_file(data_dir().join(fname));
    }
    #[test]
    fn test_lock_unlock_key() {
        init_test_data_dir();
        let key_directory = tempfile::tempdir().unwrap();
        let temp = key_directory.path().join("test_lock_unlock_key.pem");
        let key_path = temp.to_string_lossy().into_owned();
        gen_master_key(&mut PasswordType::Key(key_path.clone()), true);
        let filename = random_vault_filename();
        let vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: filename.clone(),
            },
            recovery: RecoveryData::default(),
        };
        let pass = PasswordType::Key(key_path.clone());
        let pass1 = PasswordType::Key(key_path);
        vlt.lock_vault(&mut ServerInfo {
            locked: false,
            keypass: Some(pass),
        });
        let vlt1 = unlock_vault(&mut ServerInfo {
            locked: true,
            keypass: Some(pass1),
        })
        .unwrap();
        let data_path = data_dir();
        let file_path = data_path.join(&filename);
        fs::remove_file(temp).unwrap();
        fs::remove_file(file_path).unwrap();
        assert_eq!(vlt.entries, vlt1.entries);
        assert_eq!(vlt.metadata, vlt1.metadata);
        assert_eq!(vlt1.recovery.next_entry_id, 2);
    }
    #[test]
    fn test_lock_unlock_password() {
        init_test_data_dir();
        let filename = random_vault_filename();
        let vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: filename.clone(),
            },
            recovery: RecoveryData::default(),
        };
        let pass = PasswordType::Password("test_password1234!".to_string());
        let pass1 = PasswordType::Password("test_password1234!".to_string());
        vlt.lock_vault(&mut ServerInfo {
            locked: false,
            keypass: Some(pass),
        });
        let vlt1 = unlock_vault(&mut ServerInfo {
            locked: true,
            keypass: Some(pass1),
        })
        .unwrap();
        let data_path = data_dir();
        let file_path = data_path.join(&filename);
        fs::remove_file(file_path).unwrap();
        assert_eq!(vlt.entries, vlt1.entries);
        assert_eq!(vlt.metadata, vlt1.metadata);
        assert_eq!(vlt1.recovery.next_entry_id, 2);
    }

    #[test]
    fn unlock_migrates_deterministic_password_filename() {
        init_test_data_dir();
        let unique = format!("migration-{:016x}", rand::random::<u64>());
        let mut password = PasswordType::Password(unique);
        let old_filename = try_get_deterministic_filename(&mut password).unwrap();
        let vault = Vault {
            metadata: VaultMetadata {
                filename: old_filename.clone(),
            },
            ..Vault::default()
        };
        write_vault_with_key(&vault, &mut password).unwrap();

        let mut server_info = ServerInfo {
            locked: true,
            keypass: Some(password),
        };
        let migrated = unlock_vault(&mut server_info).unwrap();

        let preferred_filename = migrated.metadata.filename.clone();
        assert_ne!(old_filename, preferred_filename);
        assert!(data_dir().join(&preferred_filename).is_file());
        assert!(!data_dir().join(old_filename).exists());
        fs::remove_file(data_dir().join(preferred_filename)).unwrap();
    }
    #[test]
    fn test_create_vault_key() {
        init_test_data_dir();
        let key_directory = tempfile::tempdir().unwrap();
        let key_path = key_directory.path().join("create_vault.enc");
        let key_path = key_path.to_string_lossy().into_owned();
        let mut vlt = None;
        create_vault(
            &mut vlt,
            &mut ServerInfo {
                locked: true,
                keypass: Some(PasswordType::Key(key_path.clone())),
            },
            false,
        )
        .unwrap();
        let filename = vlt.as_ref().unwrap().metadata.filename.clone();
        let data_path = data_dir();
        let file_path = data_path.join(&filename);
        fs::remove_file(file_path).unwrap();
        fs::remove_file(key_path).unwrap();
        assert_eq!(
            vlt,
            Some(Vault {
                entries: Vec::new(),
                metadata: VaultMetadata { filename },
                recovery: RecoveryData::default(),
            })
        )
    }
    #[test]
    fn test_create_vault_key_lock() {
        init_test_data_dir();
        let key_directory = tempfile::tempdir().unwrap();
        let key_path = key_directory.path().join("create_vault_lock.enc");
        let key_path = key_path.to_string_lossy().into_owned();
        let mut vlt = None;
        create_vault(
            &mut vlt,
            &mut ServerInfo {
                locked: true,
                keypass: Some(PasswordType::Key(key_path.clone())),
            },
            true,
        )
        .unwrap();
        let (filename, mut stored, _) =
            find_vault(&mut PasswordType::Key(key_path.clone())).unwrap();
        stored.zeroize();
        let data_path = data_dir();
        let file_path = data_path.join(&filename);
        fs::remove_file(file_path).unwrap();
        fs::remove_file(key_path).unwrap();
        assert_eq!(vlt, None)
    }

    #[test]
    fn delete_key_vault_removes_external_key_by_default() {
        init_test_data_dir();
        let key_directory = tempfile::tempdir().unwrap();
        let key_path = key_directory.path().join("delete-vault.key");
        let key_path = key_path.to_string_lossy().into_owned();
        let mut vault = None;
        let mut server_info = ServerInfo {
            locked: true,
            keypass: Some(PasswordType::Key(key_path.clone())),
        };
        create_vault(&mut vault, &mut server_info, true).unwrap();
        let (filename, mut stored, _) =
            find_vault(&mut PasswordType::Key(key_path.clone())).unwrap();
        stored.zeroize();

        delete_vault(PasswordType::Key(key_path.clone()), false).unwrap();

        assert!(!data_dir().join(filename).exists());
        assert!(!Path::new(&key_path).exists());
    }

    #[test]
    fn delete_key_vault_can_preserve_external_key() {
        init_test_data_dir();
        let key_directory = tempfile::tempdir().unwrap();
        let key_path = key_directory.path().join("keep-vault.key");
        let key_path = key_path.to_string_lossy().into_owned();
        let mut vault = None;
        let mut server_info = ServerInfo {
            locked: true,
            keypass: Some(PasswordType::Key(key_path.clone())),
        };
        create_vault(&mut vault, &mut server_info, true).unwrap();
        let (filename, mut stored, _) =
            find_vault(&mut PasswordType::Key(key_path.clone())).unwrap();
        stored.zeroize();

        delete_vault(PasswordType::Key(key_path.clone()), true).unwrap();

        assert!(!data_dir().join(filename).exists());
        assert!(Path::new(&key_path).is_file());
    }
    #[test]
    fn test_create_vault_password() {
        init_test_data_dir();
        let mut vlt = None;
        create_vault(
            &mut vlt,
            &mut ServerInfo {
                locked: true,
                keypass: Some(PasswordType::Password("test123456!".to_string())),
            },
            false,
        )
        .unwrap();
        let filename = vlt.as_ref().unwrap().metadata.filename.clone();
        let data_path = data_dir();
        let file_path = data_path.join(&filename);
        fs::remove_file(file_path).unwrap();
        assert_eq!(
            vlt,
            Some(Vault {
                entries: Vec::new(),
                metadata: VaultMetadata { filename },
                recovery: RecoveryData::default(),
            })
        )
    }
    #[test]
    fn test_create_vault_password_lock() {
        init_test_data_dir();
        let mut vlt = None;
        create_vault(
            &mut vlt,
            &mut ServerInfo {
                locked: true,
                keypass: Some(PasswordType::Password("test1234567!".to_string())),
            },
            true,
        )
        .unwrap();
        let (filename, mut stored, _) =
            find_vault(&mut PasswordType::Password("test1234567!".to_string())).unwrap();
        stored.zeroize();
        let data_path = data_dir();
        let file_path = data_path.join(&filename);
        fs::remove_file(file_path).unwrap();
        assert_eq!(vlt, None)
    }

    #[test]
    fn test_rekey_replaces_vault_and_new_password_unlocks() {
        init_test_data_dir();
        let unique = format!("{:016x}", rand::random::<u64>());
        let mut server_info = ServerInfo {
            locked: false,
            keypass: Some(PasswordType::Password(format!("old-{unique}"))),
        };
        let mut vault = None;
        create_vault(&mut vault, &mut server_info, false).unwrap();
        let old_path = data_dir().join(&vault.as_ref().unwrap().metadata.filename);
        let new_password = PasswordType::Password(format!("new-{unique}"));
        vault
            .as_mut()
            .unwrap()
            .rekey(&mut server_info, new_password.clone())
            .unwrap();
        let new_path = data_dir().join(&vault.as_ref().unwrap().metadata.filename);
        assert!(!old_path.exists());
        assert!(new_path.exists());
        let mut unlock_info = ServerInfo {
            locked: true,
            keypass: Some(new_password),
        };
        assert!(unlock_vault(&mut unlock_info).is_some());
        fs::remove_file(new_path).unwrap();
    }
    #[test]
    fn test_add_duplicate_entry_name() {
        let mut vlt = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt.add_entry(
            PasswordEntry {
                name: String::from("test"),
                username: Some(String::from("user1")),
                password: String::from("pass1"),
                url: None,
                notes: None,
                copy: false,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        let initial_len = vlt.entries.len();

        // Same name, different username -> allowed (multiple accounts per site)
        vlt.add_entry(
            PasswordEntry {
                name: String::from("test"),
                username: Some(String::from("user2")),
                password: String::from("pass2"),
                url: None,
                notes: None,
                copy: false,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.entries.len(), initial_len + 1);

        // Same name AND same username -> still blocked
        vlt.add_entry(
            PasswordEntry {
                name: String::from("test"),
                username: Some(String::from("user1")),
                password: String::from("pass3"),
                url: None,
                notes: None,
                copy: false,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.entries.len(), initial_len + 1);
    }
    #[test]
    fn test_add_multiple_entries_ids_sequential() {
        let mut vlt = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        for i in 0..5 {
            vlt.add_entry(
                PasswordEntry {
                    name: format!("entry{}", i),
                    username: Some(format!("user{}", i)),
                    password: format!("pass{}", i),
                    url: None,
                    notes: None,
                    copy: false,
                },
                &mut ServerInfo {
                    locked: true,
                    keypass: None,
                },
            );
        }
        for (i, entry) in vlt.entries.iter().enumerate() {
            assert_eq!(entry.id, i + 1);
        }
    }
    #[test]
    fn test_delete_entry_preserves_other_ids() {
        let mut vlt = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        for i in 0..5 {
            vlt.add_entry(
                PasswordEntry {
                    name: format!("entry{}", i),
                    username: Some(format!("user{}", i)),
                    password: format!("pass{}", i),
                    url: None,
                    notes: None,
                    copy: false,
                },
                &mut ServerInfo {
                    locked: true,
                    keypass: None,
                },
            );
        }
        vlt.delete_entry(
            Target::Id(2),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(
            vlt.entries.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![1, 3, 4, 5]
        );
    }
    #[test]
    fn test_update_password_changes() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("oldpass"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt.update_entry(
            EntryUpdate {
                target: Target::Id(1),
                update: UpdateArgs {
                    name: None,
                    username: None,
                    password: true,
                    generate_password: false,
                    url: None,
                    notes: None,
                },
                password: Some(String::from("newpass")),
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.entries[0].password, "newpass");
    }
    #[test]
    fn test_update_url_changes() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt.update_entry(
            EntryUpdate {
                target: Target::Id(1),
                update: UpdateArgs {
                    name: None,
                    username: None,
                    password: false,
                    generate_password: false,
                    url: Some(String::from("https://example.com")),
                    notes: None,
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(
            vlt.entries[0].url,
            Some(String::from("https://example.com"))
        );
    }
    #[test]
    fn test_update_notes_changes() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt.update_entry(
            EntryUpdate {
                target: Target::Id(1),
                update: UpdateArgs {
                    name: None,
                    username: None,
                    password: false,
                    generate_password: false,
                    url: None,
                    notes: Some(String::from("important notes")),
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.entries[0].notes, Some(String::from("important notes")));
    }

    #[test]
    fn test_delete_entry_invalid_id_zero() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        let result = vlt.delete_entry(
            Target::Id(0),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert!(!result.unwrap());
    }

    #[test]
    fn test_delete_entry_invalid_id_out_of_bounds() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        let result = vlt.delete_entry(
            Target::Id(100),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert!(!result.unwrap());
    }

    #[test]
    fn test_update_entry_invalid_id_zero() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        let result = vlt.update_entry(
            EntryUpdate {
                target: Target::Id(0),
                update: UpdateArgs {
                    name: Some(String::from("new")),
                    username: None,
                    password: false,
                    generate_password: false,
                    url: None,
                    notes: None,
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert!(!result.unwrap());
    }

    #[test]
    fn test_update_entry_invalid_id_out_of_bounds() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        let result = vlt.update_entry(
            EntryUpdate {
                target: Target::Id(100),
                update: UpdateArgs {
                    name: Some(String::from("new")),
                    username: None,
                    password: false,
                    generate_password: false,
                    url: None,
                    notes: None,
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert!(!result.unwrap());
    }

    #[test]
    fn test_delete_entry_by_name_no_match() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        let initial_len = vlt.entries.len();
        vlt.delete_entry(
            Target::Name("nonexistent".into()),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.entries.len(), initial_len);
    }

    #[test]
    fn test_update_entry_by_name_no_match() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        let original_modified = vlt.entries[0].modified.clone();
        vlt.update_entry(
            EntryUpdate {
                target: Target::Name(String::from("nonexistent")),
                update: UpdateArgs {
                    name: Some(String::from("new")),
                    username: None,
                    password: false,
                    generate_password: false,
                    url: None,
                    notes: None,
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.entries[0].name, "test");
        assert_eq!(vlt.entries[0].modified, original_modified);
    }

    #[test]
    fn test_delete_name_with_only_first_match() {
        let mut vlt = Vault {
            entries: vec![
                VaultEntry {
                    id: 1,
                    name: String::from("dup"),
                    username: Some(String::from("user1")),
                    password: String::from("pass1"),
                    url: None,
                    notes: None,
                    created: chrono::Local::now().to_string(),
                    modified: chrono::Local::now().to_string(),
                },
                VaultEntry {
                    id: 2,
                    name: String::from("dup"),
                    username: Some(String::from("user2")),
                    password: String::from("pass2"),
                    url: None,
                    notes: None,
                    created: chrono::Local::now().to_string(),
                    modified: chrono::Local::now().to_string(),
                },
            ],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt.delete_entry(
            Target::Name("dup".into()),
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.entries.len(), 1);
        assert_eq!(vlt.entries[0].id, 2);
        assert_eq!(vlt.entries[0].username, Some(String::from("user2")));
    }

    #[test]
    fn test_add_entry_with_all_fields() {
        let mut vlt: Vault = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt.add_entry(
            PasswordEntry {
                name: String::from("full_entry"),
                username: Some(String::from("admin")),
                password: String::from("secret123"),
                url: Some(String::from("https://example.com")),
                notes: Some(String::from("important account")),
                copy: false,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.entries.len(), 1);
        assert_eq!(vlt.entries[0].name, "full_entry");
        assert_eq!(vlt.entries[0].username, Some(String::from("admin")));
        assert_eq!(vlt.entries[0].password, "secret123");
        assert_eq!(
            vlt.entries[0].url,
            Some(String::from("https://example.com"))
        );
        assert_eq!(
            vlt.entries[0].notes,
            Some(String::from("important account"))
        );
    }

    #[test]
    fn test_add_entry_with_minimal_fields() {
        let mut vlt: Vault = Vault {
            entries: vec![],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        vlt.add_entry(
            PasswordEntry {
                name: String::from("minimal"),
                username: None,
                password: String::from("pass"),
                url: None,
                notes: None,
                copy: false,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.entries.len(), 1);
        assert_eq!(vlt.entries[0].name, "minimal");
        assert_eq!(vlt.entries[0].username, None);
        assert_eq!(vlt.entries[0].url, None);
        assert_eq!(vlt.entries[0].notes, None);
    }

    #[test]
    fn test_update_all_fields_at_once() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("original"),
                username: Some(String::from("old_user")),
                password: String::from("old_pass"),
                url: Some(String::from("http://old.com")),
                notes: Some(String::from("old notes")),
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        let original_created = vlt.entries[0].created.clone();
        vlt.update_entry(
            EntryUpdate {
                target: Target::Id(1),
                update: UpdateArgs {
                    name: Some(String::from("new_name")),
                    username: Some(String::from("new_user")),
                    password: true,
                    generate_password: false,
                    url: Some(String::from("https://new.com")),
                    notes: Some(String::from("new notes")),
                },
                password: Some(String::from("new_pass")),
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.entries[0].name, "new_name");
        assert_eq!(vlt.entries[0].username, Some(String::from("new_user")));
        assert_eq!(vlt.entries[0].password, "new_pass");
        assert_eq!(vlt.entries[0].url, Some(String::from("https://new.com")));
        assert_eq!(vlt.entries[0].notes, Some(String::from("new notes")));
        assert_eq!(vlt.entries[0].created, original_created);
    }

    #[test]
    fn test_update_no_changes() {
        let mut vlt = Vault {
            entries: vec![VaultEntry {
                id: 1,
                name: String::from("test"),
                username: Some(String::from("test")),
                password: String::from("test123"),
                url: None,
                notes: None,
                created: chrono::Local::now().to_string(),
                modified: chrono::Local::now().to_string(),
            }],
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        };
        let original_modified = vlt.entries[0].modified.clone();
        thread::sleep(std::time::Duration::from_millis(10));
        vlt.update_entry(
            EntryUpdate {
                target: Target::Id(1),
                update: UpdateArgs {
                    name: None,
                    username: None,
                    password: false,
                    generate_password: false,
                    url: None,
                    notes: None,
                },
                password: None,
            },
            &mut ServerInfo {
                locked: true,
                keypass: None,
            },
        );
        assert_eq!(vlt.entries[0].modified, original_modified);
    }

    fn recovery_test_vault(entries: Vec<VaultEntry>) -> Vault {
        Vault {
            entries,
            metadata: VaultMetadata {
                filename: "test.enc".into(),
            },
            recovery: RecoveryData::default(),
        }
    }

    fn recovery_test_entry(id: usize, name: &str, username: &str, password: &str) -> VaultEntry {
        VaultEntry {
            id,
            name: name.into(),
            username: Some(username.into()),
            password: password.into(),
            url: Some("example.com".into()),
            notes: None,
            created: "created".into(),
            modified: "modified".into(),
        }
    }

    #[test]
    fn password_updates_create_restorable_history() {
        let mut vault = recovery_test_vault(vec![recovery_test_entry(1, "site", "alice", "old")]);
        let mut server_info = ServerInfo::default();
        vault
            .update_entry(
                EntryUpdate {
                    target: Target::Id(1),
                    update: UpdateArgs {
                        name: None,
                        username: None,
                        password: true,
                        generate_password: false,
                        url: None,
                        notes: None,
                    },
                    password: Some("new".into()),
                },
                &mut server_info,
            )
            .unwrap();
        assert_eq!(vault.recovery.password_history[0].password, "old");
        vault
            .restore_password(Target::Id(1), 1, &mut server_info)
            .unwrap();
        assert_eq!(vault.entries[0].password, "old");
        assert_eq!(vault.recovery.password_history[0].password, "new");
    }

    #[test]
    fn delete_restore_and_purge_use_encrypted_trash_state() {
        let mut vault = recovery_test_vault(vec![recovery_test_entry(1, "site", "alice", "pass")]);
        let mut server_info = ServerInfo::default();
        assert!(vault.delete_entry(Target::Id(1), &mut server_info).unwrap());
        assert!(vault.entries.is_empty());
        assert_eq!(vault.recovery.trash.len(), 1);
        assert!(vault.restore_trashed(1, &mut server_info).unwrap());
        assert_eq!(vault.entries[0].name, "site");
        assert!(vault.recovery.trash.is_empty());
        vault.delete_entry(Target::Id(1), &mut server_info).unwrap();
        assert!(vault.purge_trash(None, &mut server_info).unwrap());
        assert!(vault.recovery.trash.is_empty());
    }

    #[test]
    fn password_history_is_bounded() {
        let mut vault = recovery_test_vault(vec![recovery_test_entry(1, "site", "alice", "p0")]);
        for index in 1..=15 {
            let old = std::mem::replace(&mut vault.entries[0].password, format!("p{index}"));
            vault.push_password_history(1, old);
        }
        assert_eq!(
            vault.recovery.password_history.len(),
            Vault::MAX_PASSWORD_HISTORY
        );
        assert_eq!(vault.recovery.password_history[0].password, "p5");
    }

    #[test]
    fn stable_ids_survive_delete_add_and_restore() {
        let mut vault = recovery_test_vault(vec![
            recovery_test_entry(4, "first", "alice", "one"),
            recovery_test_entry(9, "second", "bob", "two"),
        ]);
        let mut server_info = ServerInfo::default();

        assert!(vault.delete_entry(Target::Id(4), &mut server_info).unwrap());
        assert_eq!(vault.entries[0].id, 9);
        vault
            .add_entry(
                PasswordEntry {
                    name: "third".into(),
                    username: Some("carol".into()),
                    password: "three".into(),
                    url: None,
                    notes: None,
                    copy: false,
                },
                &mut server_info,
            )
            .unwrap();
        assert_eq!(vault.entries[1].id, 10);

        assert!(vault.restore_trashed(1, &mut server_info).unwrap());
        assert_eq!(vault.entries[2].id, 4);
        assert_eq!(vault.recovery.next_entry_id, 11);

        vault
            .delete_entry(Target::Id(10), &mut server_info)
            .unwrap();
        vault.purge_trash(None, &mut server_info).unwrap();
        vault
            .add_entry(
                PasswordEntry {
                    name: "fourth".into(),
                    username: Some("dana".into()),
                    password: "four".into(),
                    url: None,
                    notes: None,
                    copy: false,
                },
                &mut server_info,
            )
            .unwrap();
        assert_eq!(vault.entries.last().unwrap().id, 11);
    }

    #[test]
    fn search_is_case_insensitive_combines_filters_and_excludes_passwords() {
        let mut first = recovery_test_entry(3, "GitHub", "Alice", "hidden-token");
        first.url = Some("https://github.com/login".into());
        first.notes = Some("Personal account".into());
        let mut second = recovery_test_entry(8, "GitLab", "alice-work", "different-secret");
        second.url = Some("https://gitlab.example".into());
        second.notes = Some("Work account".into());
        let vault = recovery_test_vault(vec![first, second]);

        let query_results = vault.search_entries(&SearchFilter {
            query: Some("ALICE".into()),
            ..SearchFilter::default()
        });
        assert_eq!(query_results.len(), 2);

        let filtered = vault.search_entries(&SearchFilter {
            name: Some("git".into()),
            url: Some("github.com".into()),
            notes: Some("personal".into()),
            ..SearchFilter::default()
        });
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].id, 3);

        let password_results = vault.search_entries(&SearchFilter {
            query: Some("hidden-token".into()),
            ..SearchFilter::default()
        });
        assert!(password_results.is_empty());
    }

    #[test]
    fn additional_urls_are_searchable_and_used_only_for_login_autofill() {
        let login = recovery_test_entry(3, "Example", "alice", "strong-enough-secret");
        let note = recovery_test_entry(4, "Private note", "", "not-for-the-browser");
        let metadata = vec![
            EntryMetadata {
                entry_id: 3,
                kind: ItemKind::Login,
                additional_urls: vec!["https://accounts.example.net/login".into()],
                password_changed: None,
                custom_fields: Vec::new(),
            },
            EntryMetadata {
                entry_id: 4,
                kind: ItemKind::SecureNote,
                additional_urls: vec!["https://notes.example.net".into()],
                password_changed: None,
                custom_fields: Vec::new(),
            },
        ];
        let mut vault = recovery_test_vault(vec![login.clone(), note.clone()]);
        vault.recovery.entry_metadata = metadata.clone();

        let matches = vault.search_entries(&SearchFilter {
            url: Some("accounts.example.net".into()),
            ..SearchFilter::default()
        });
        assert_eq!(
            matches.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            [3]
        );
        assert!(url_match_json(&[login], &[], &metadata, "accounts.example.net").is_some());
        assert!(url_match_json(&[note], &[], &metadata, "notes.example.net").is_none());
    }

    #[test]
    fn typed_add_and_update_persist_item_metadata_by_stable_id() {
        let mut vault = recovery_test_vault(Vec::new());
        let mut server_info = ServerInfo::default();
        assert!(
            vault
                .add_typed_entry(
                    TypedEntry {
                        entry: PasswordEntry {
                            name: "Router".into(),
                            username: Some("WPA3".into()),
                            password: "network-secret".into(),
                            url: Some("https://router.example".into()),
                            notes: None,
                            copy: false,
                        },
                        kind: ItemKind::Wifi,
                        additional_urls: vec![
                            "https://backup-router.example".into(),
                            "https://backup-router.example".into(),
                        ],
                        custom_fields: vec![
                            CustomField {
                                name: "location".into(),
                                value: "upstairs".into(),
                                secret: false,
                            },
                            CustomField {
                                name: "admin-pin".into(),
                                value: "8192".into(),
                                secret: true,
                            },
                        ],
                    },
                    &mut server_info,
                )
                .unwrap()
        );
        let entry_id = vault.entries[0].id;
        assert_eq!(vault.item_kind(entry_id), ItemKind::Wifi);
        assert_eq!(vault.custom_fields(entry_id).len(), 2);
        assert_eq!(
            vault
                .search_entries(&SearchFilter {
                    query: Some("upstairs".into()),
                    ..SearchFilter::default()
                })
                .len(),
            1
        );
        assert!(
            vault
                .search_entries(&SearchFilter {
                    query: Some("8192".into()),
                    ..SearchFilter::default()
                })
                .is_empty()
        );
        assert_eq!(
            vault.all_urls(&vault.entries[0]).collect::<Vec<_>>(),
            ["https://router.example", "https://backup-router.example"]
        );

        assert!(
            vault
                .update_typed_entry(
                    TypedUpdate {
                        entry: EntryUpdate {
                            target: Target::Id(entry_id),
                            update: UpdateArgs {
                                name: None,
                                username: None,
                                password: false,
                                generate_password: false,
                                url: None,
                                notes: None,
                            },
                            password: None,
                        },
                        kind: Some(ItemKind::Login),
                        add_url: vec!["https://new.example".into()],
                        remove_url: vec!["https://router.example".into()],
                        clear_urls: false,
                        set_fields: vec![CustomField {
                            name: "location".into(),
                            value: "downstairs".into(),
                            secret: false,
                        }],
                        remove_fields: vec!["admin-pin".into()],
                        clear_fields: false,
                    },
                    &mut server_info,
                )
                .unwrap()
        );
        assert_eq!(vault.item_kind(entry_id), ItemKind::Login);
        assert_eq!(
            vault.custom_fields(entry_id),
            [CustomField {
                name: "location".into(),
                value: "downstairs".into(),
                secret: false,
            }]
        );
        assert_eq!(
            vault.all_urls(&vault.entries[0]).collect::<Vec<_>>(),
            ["https://backup-router.example", "https://new.example"]
        );
    }

    #[test]
    fn import_preview_and_conflict_policies_are_deterministic() {
        let mut existing = recovery_test_entry(7, "Example", "alice", "old-password");
        existing.url = Some("https://example.com".into());
        let mut vault = recovery_test_vault(vec![existing]);
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "name,username,password,url").unwrap();
        writeln!(file, "Example,alice,new-password,https://example.com").unwrap();
        let path = file.path().display().to_string();
        let mut server_info = ServerInfo::default();

        let before = vault.clone();
        let preview = vault
            .import_with_options(
                path.clone(),
                ConflictPolicy::Replace,
                true,
                1,
                &mut server_info,
            )
            .unwrap();
        assert_eq!(preview.total, 1);
        assert_eq!(preview.replaced, 1);
        assert_eq!(vault, before);

        let replaced = vault
            .import_with_options(
                path.clone(),
                ConflictPolicy::Replace,
                false,
                1,
                &mut server_info,
            )
            .unwrap();
        assert_eq!(replaced.replaced, 1);
        assert_eq!(vault.entries[0].id, 7);
        assert_eq!(vault.entries[0].password, "new-password");
        assert_eq!(vault.recovery.password_history.len(), 1);

        let kept = vault
            .import_with_options(path, ConflictPolicy::KeepBoth, false, 1, &mut server_info)
            .unwrap();
        assert_eq!(kept.renamed, 1);
        assert_eq!(vault.entries.len(), 2);
        assert_eq!(vault.entries[1].name, "Example (imported)");
    }

    #[test]
    fn recovery_limits_bound_history_and_expire_old_trash() {
        let mut vault = recovery_test_vault(Vec::new());
        vault.push_password_history_with_limit(1, "one".into(), 2);
        vault.push_password_history_with_limit(1, "two".into(), 2);
        vault.push_password_history_with_limit(1, "three".into(), 2);
        assert_eq!(vault.recovery.password_history.len(), 2);
        vault.push_password_history_with_limit(1, "discarded".into(), 0);
        assert_eq!(vault.recovery.password_history.len(), 2);

        let old = TrashedEntry {
            entry: recovery_test_entry(11, "old", "alice", "secret"),
            history: Vec::new(),
            deleted: (chrono::Local::now() - chrono::Duration::days(60)).to_string(),
        };
        let recent = TrashedEntry {
            entry: recovery_test_entry(12, "recent", "bob", "secret"),
            history: Vec::new(),
            deleted: chrono::Local::now().to_string(),
        };
        vault.recovery.trash = vec![old, recent];
        vault.recovery.entry_metadata.push(EntryMetadata {
            entry_id: 11,
            ..EntryMetadata::default()
        });
        vault.recovery.totp.push(TotpRecord {
            entry_id: 11,
            configuration: "secret".into(),
        });
        let purged = vault
            .purge_expired_trash(30, &mut ServerInfo::default())
            .unwrap();
        assert_eq!(purged, 1);
        assert_eq!(vault.recovery.trash[0].entry.id, 12);
        assert!(vault.recovery.entry_metadata.is_empty());
        assert!(vault.recovery.totp.is_empty());
    }

    #[test]
    fn list_options_filter_item_type_totp_and_weakness_and_sort_results() {
        let mut alpha = recovery_test_entry(8, "Alpha", "alice", "A-very-long-unique-password-42!");
        alpha.created = "2024-01-01".into();
        let mut beta = recovery_test_entry(2, "beta", "bob", "password");
        beta.created = "2023-01-01".into();
        let mut vault = recovery_test_vault(vec![alpha, beta]);
        vault.recovery.entry_metadata = vec![EntryMetadata {
            entry_id: 2,
            kind: ItemKind::Wifi,
            additional_urls: Vec::new(),
            password_changed: Some("2025-01-01T00:00:00Z".into()),
            custom_fields: Vec::new(),
        }];
        vault.recovery.totp.push(TotpRecord {
            entry_id: 8,
            configuration: "secret".into(),
        });

        let typed = vault.apply_list_options(
            vault.entries.iter().collect(),
            &ListOptions {
                kind: Some(ItemKind::Wifi),
                ..ListOptions::default()
            },
        );
        assert_eq!(typed.iter().map(|entry| entry.id).collect::<Vec<_>>(), [2]);

        let with_totp = vault.apply_list_options(
            vault.entries.iter().collect(),
            &ListOptions {
                has_totp: Some(true),
                ..ListOptions::default()
            },
        );
        assert_eq!(
            with_totp.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            [8]
        );

        let weak = vault.apply_list_options(
            vault.entries.iter().collect(),
            &ListOptions {
                weak: true,
                ..ListOptions::default()
            },
        );
        assert_eq!(weak.iter().map(|entry| entry.id).collect::<Vec<_>>(), [2]);

        let stale = vault.apply_list_options(
            vault.entries.iter().collect(),
            &ListOptions {
                stale_days: Some(365),
                ..ListOptions::default()
            },
        );
        assert_eq!(stale.iter().map(|entry| entry.id).collect::<Vec<_>>(), [2]);

        let sorted = vault.apply_list_options(
            vault.entries.iter().collect(),
            &ListOptions {
                sort: SortField::Name,
                descending: true,
                ..ListOptions::default()
            },
        );
        assert_eq!(
            sorted.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            [2, 8]
        );
    }

    #[test]
    fn totp_matches_rfc_6238_sha1_vectors() {
        let raw = "GEZD GNBV-GY3TQOJQ GEZDGNBVGY3TQOJQ";
        let (normalized, bits) = normalize_totp_configuration(raw).unwrap();
        assert_eq!(normalized, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(bits, 160);
        let totp = parse_totp_configuration(&normalized).unwrap();
        assert_eq!(totp.generate(59).to_string(), "287082");

        let uri = "otpauth://totp/RFC?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30";
        let totp = parse_totp_configuration(uri).unwrap();
        assert_eq!(totp.generate(59).to_string(), "94287082");
    }

    #[test]
    fn totp_accepts_github_compatible_80_bit_secrets() {
        let github_secret = "GEZDGNBVGY3TQOJQ";
        let (normalized, bits) = normalize_totp_configuration(github_secret).unwrap();
        assert_eq!(bits, 80);
        let raw_totp = parse_totp_configuration(&normalized).unwrap();

        let uri = format!(
            "otpauth://totp/GitHub:test?secret={github_secret}&issuer=GitHub&algorithm=SHA1&digits=6&period=30"
        );
        let (normalized_uri, uri_bits) = normalize_totp_configuration(&uri).unwrap();
        assert_eq!(uri_bits, 80);
        let uri_totp = parse_totp_configuration(&normalized_uri).unwrap();
        assert_eq!(raw_totp.generate(59), uri_totp.generate(59));

        assert!(normalize_totp_configuration("GEZDGNBVGY3TQ").is_err());
    }

    #[test]
    fn totp_follows_trash_restore_and_is_erased_on_purge() {
        let mut vault =
            recovery_test_vault(vec![recovery_test_entry(7, "service", "alice", "password")]);
        let mut server_info = ServerInfo::default();
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

        assert_eq!(
            vault
                .set_totp(Target::Id(7), secret, &mut server_info)
                .unwrap(),
            Some(160)
        );
        assert_eq!(vault.totp_at(&Target::Id(7), 59).unwrap().0, "287082");

        vault.delete_entry(Target::Id(7), &mut server_info).unwrap();
        assert!(vault.totp_at(&Target::Id(7), 59).is_err());
        assert_eq!(vault.recovery.totp[0].entry_id, 7);
        vault.restore_trashed(1, &mut server_info).unwrap();
        assert_eq!(vault.totp_at(&Target::Id(7), 59).unwrap().0, "287082");

        vault.delete_entry(Target::Id(7), &mut server_info).unwrap();
        vault.purge_trash(None, &mut server_info).unwrap();
        assert!(vault.recovery.totp.is_empty());
    }

    #[test]
    fn totp_rejects_invalid_configuration_and_can_be_removed() {
        let mut vault =
            recovery_test_vault(vec![recovery_test_entry(1, "service", "alice", "password")]);
        let mut server_info = ServerInfo::default();
        assert!(
            vault
                .set_totp(Target::Id(1), "not base32!", &mut server_info)
                .is_err()
        );
        assert!(vault.recovery.totp.is_empty());

        vault
            .set_totp(
                Target::Id(1),
                "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
                &mut server_info,
            )
            .unwrap();
        assert!(vault.remove_totp(Target::Id(1), &mut server_info).unwrap());
        assert!(vault.recovery.totp.is_empty());
        assert!(!vault.remove_totp(Target::Id(1), &mut server_info).unwrap());
    }

    #[test]
    fn old_recovery_data_defaults_to_no_totp_records() {
        #[derive(Serialize)]
        struct LegacyRecoveryData {
            password_history: Vec<PasswordRevision>,
            trash: Vec<TrashedEntry>,
            next_entry_id: usize,
        }

        let encoded = rmp_serde::to_vec(&LegacyRecoveryData {
            password_history: Vec::new(),
            trash: Vec::new(),
            next_entry_id: 12,
        })
        .unwrap();
        let decoded: RecoveryData = rmp_serde::from_slice(&encoded).unwrap();
        assert_eq!(decoded.next_entry_id, 12);
        assert!(decoded.totp.is_empty());
    }

    #[test]
    fn totp_secrets_are_redacted_and_only_in_full_fidelity_json_exports() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let mut vault =
            recovery_test_vault(vec![recovery_test_entry(1, "service", "alice", "password")]);
        vault
            .set_totp(Target::Id(1), secret, &mut ServerInfo::default())
            .unwrap();
        assert!(!format!("{:?}", vault.recovery.totp[0]).contains(secret));

        let directory = tempfile::tempdir().unwrap();
        let json_path = directory.path().join("export.json");
        vault.export(json_path.display().to_string()).unwrap();
        assert!(fs::read_to_string(json_path).unwrap().contains(secret));

        let csv_path = directory.path().join("export.csv");
        vault.export(csv_path.display().to_string()).unwrap();
        assert!(!fs::read_to_string(csv_path).unwrap().contains(secret));
    }

    #[cfg(unix)]
    #[test]
    fn plaintext_exports_are_created_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let vault = recovery_test_vault(vec![recovery_test_entry(
            1,
            "service",
            "alice",
            "exported-secret",
        )]);
        for extension in ["json", "csv"] {
            let path = directory.path().join(format!("export.{extension}"));
            vault.export(path.display().to_string()).unwrap();
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn encrypted_backup_round_trip_preserves_complete_vault_state() {
        init_test_data_dir();
        let directory = tempfile::tempdir().unwrap();
        let backup_path = directory.path().join("complete.pmbackup");
        let totp_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let mut vault = recovery_test_vault(vec![recovery_test_entry(
            1,
            "active-service",
            "alice",
            "active-password",
        )]);
        vault.recovery.next_entry_id = 3;
        vault.recovery.password_history.push(PasswordRevision {
            entry_id: 1,
            password: "previous-password".into(),
            changed: "yesterday".into(),
        });
        vault.recovery.trash.push(TrashedEntry {
            entry: recovery_test_entry(2, "deleted-service", "bob", "deleted-password"),
            history: vec![PasswordRevision {
                entry_id: 2,
                password: "deleted-previous".into(),
                changed: "last-week".into(),
            }],
            deleted: "today".into(),
        });
        vault.recovery.totp.extend([
            TotpRecord {
                entry_id: 1,
                configuration: totp_secret.into(),
            },
            TotpRecord {
                entry_id: 2,
                configuration: totp_secret.into(),
            },
        ]);

        let password = format!("backup-{:016x}", rand::random::<u64>());
        let mut backup_key = PasswordType::Password(password.clone());
        vault
            .encrypted_backup(backup_path.display().to_string(), &mut backup_key, false)
            .unwrap();
        let encrypted = fs::read(&backup_path).unwrap();
        assert!(encrypted.starts_with(BACKUP_MAGIC));
        assert!(
            !encrypted
                .windows(totp_secret.len())
                .any(|part| part == totp_secret.as_bytes())
        );
        assert!(
            vault
                .encrypted_backup(backup_path.display().to_string(), &mut backup_key, false,)
                .is_err()
        );
        assert_eq!(fs::read(&backup_path).unwrap(), encrypted);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&backup_path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let mut wrong_key = PasswordType::Password("wrong-backup-password".into());
        assert!(
            restore_encrypted_backup(backup_path.to_str().unwrap(), &mut wrong_key, false).is_err()
        );

        let filename =
            restore_encrypted_backup(backup_path.to_str().unwrap(), &mut backup_key, false)
                .unwrap();
        let mut restored_info = ServerInfo {
            locked: true,
            keypass: Some(PasswordType::Password(password)),
        };
        let restored = unlock_vault(&mut restored_info).unwrap();
        assert_eq!(restored.entries, vault.entries);
        assert_eq!(restored.recovery, vault.recovery);
        assert_eq!(restored.metadata.filename, filename);

        assert!(
            restore_encrypted_backup(backup_path.to_str().unwrap(), &mut backup_key, false)
                .unwrap_err()
                .contains("--force")
        );
        assert_eq!(
            restore_encrypted_backup(backup_path.to_str().unwrap(), &mut backup_key, true).unwrap(),
            filename
        );
        fs::remove_file(data_dir().join(filename)).unwrap();
    }

    #[test]
    fn encrypted_backup_rejects_tampering_and_invalid_vault_state() {
        init_test_data_dir();
        let directory = tempfile::tempdir().unwrap();
        let tampered_path = directory.path().join("tampered.pmbackup");
        let invalid_path = directory.path().join("invalid.pmbackup");
        let password = format!("adversarial-backup-{:016x}", rand::random::<u64>());
        let mut key = PasswordType::Password(password);

        let vault =
            recovery_test_vault(vec![recovery_test_entry(1, "service", "alice", "password")]);
        vault
            .encrypted_backup(tampered_path.display().to_string(), &mut key, false)
            .unwrap();
        let mut tampered = fs::read(&tampered_path).unwrap();
        *tampered.last_mut().unwrap() ^= 1;
        fs::write(&tampered_path, tampered).unwrap();
        assert!(
            restore_encrypted_backup(tampered_path.to_str().unwrap(), &mut key, false)
                .unwrap_err()
                .contains("corrupted")
        );

        let mut invalid =
            recovery_test_vault(vec![recovery_test_entry(1, "active", "alice", "password")]);
        invalid.recovery.trash.push(TrashedEntry {
            entry: recovery_test_entry(1, "deleted", "bob", "password"),
            history: Vec::new(),
            deleted: "today".into(),
        });
        let envelope = BackupEnvelopeRef {
            version: BACKUP_VERSION,
            created: chrono::Utc::now().to_rfc3339(),
            vault: &invalid,
        };
        let plaintext = rmp_serde::to_vec(&envelope).unwrap();
        let encrypted = try_encrypt_file(&mut key, &plaintext).unwrap();
        let mut contents = BACKUP_MAGIC.to_vec();
        contents.push(BACKUP_VERSION);
        contents.extend_from_slice(&encrypted);
        fs::write(&invalid_path, contents).unwrap();

        assert!(find_vault(&mut key).is_none());
        assert!(
            restore_encrypted_backup(invalid_path.to_str().unwrap(), &mut key, false)
                .unwrap_err()
                .contains("duplicate entry IDs")
        );
        assert!(find_vault(&mut key).is_none());
    }

    #[test]
    fn audit_reports_weak_reused_and_duplicate_logins_without_passwords() {
        let vault = recovery_test_vault(vec![
            recovery_test_entry(1, "first", "alice", "secret"),
            recovery_test_entry(2, "second", "alice", "secret"),
        ]);
        let report = vault.audit_report(&AuditOptions::default(), None, None);
        assert!(report.contains("2 weak entries"));
        assert!(report.contains("1 reused-password groups"));
        assert!(report.contains("1 duplicate-login groups"));
        assert!(!report.contains("secret"));
    }

    #[test]
    fn audit_reports_stale_missing_totp_and_breached_passwords() {
        let mut vault = recovery_test_vault(vec![recovery_test_entry(
            7,
            "old account",
            "alice",
            "known-breached-value",
        )]);
        vault.recovery.entry_metadata.push(EntryMetadata {
            entry_id: 7,
            password_changed: Some("2020-01-01T00:00:00Z".into()),
            ..EntryMetadata::default()
        });
        let mut breached = HashMap::new();
        breached.insert(password_hash("known-breached-value"), 42);
        let report = vault.audit_report(
            &AuditOptions {
                stale_days: Some(365),
                check_breaches: true,
                require_totp: true,
            },
            Some(&breached),
            None,
        );
        assert!(report.contains("Stale password: 7. old account"));
        assert!(report.contains("Missing TOTP: 7. old account"));
        assert!(report.contains("Breached password: 7. old account (seen 42 times)"));
        assert!(report.contains("Health score: 0/100"));
        assert!(!report.contains("known-breached-value"));
    }

    #[test]
    fn pwned_range_parser_ignores_padding_and_reconstructs_hashes() {
        let parsed = parse_pwned_range("ABCDE:0\r\n12345:9\r\n", "FFFFF");
        assert_eq!(parsed.get("FFFFF12345"), Some(&9));
        assert!(!parsed.contains_key("FFFFFABCDE"));
    }
}
