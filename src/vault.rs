#[cfg(test)]
use crate::encryption::{PRODUCTION_KDF_PARAMETERS, try_encrypt_file, with_test_kdf_parameters};
use crate::{
    encryption::{
        decrypt_file, try_encrypt_file_in_place, try_gen_master_key, validate_new_password,
    },
    file::{
        data_dir, file_exists, key_file_path, new_key_file_path, set_private_perms, sync_parent,
    },
    server::ServerInfo,
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
use totp_rs::{Builder as TotpBuilder, Secret as TotpSecret, Totp, TotpError};
use zeroize::{Zeroize, Zeroizing};

mod error;
pub use error::VaultError;
mod recovery;
mod totp;

mod browser;
mod query;
use browser::hostname;
#[cfg(test)]
use browser::hosts_match;
mod backup;
pub(crate) use backup::restore_encrypted_backup;
mod entries;
mod export;

mod persistence;
use persistence::unlock_vault;
pub(crate) use persistence::{create_vault, delete_vault};
use persistence::{
    find_vault, persist_private_file, random_vault_filename, write_vault, write_vault_with_key,
};
mod transaction;
use transaction::TransactionScope;

/// Borrowed domain records; rendering does not require cloning vault secrets.
pub struct EntryView<'a> {
    pub entry: &'a VaultEntry,
    pub metadata: Option<&'a EntryMetadata>,
    pub has_totp: bool,
    pub urls: Vec<&'a str>,
}

pub enum EntryOutput<'a> {
    Details(EntryView<'a>),
    SiteLogins(Zeroizing<String>),
}

pub struct TrashView<'a> {
    pub entry: EntryView<'a>,
    pub deleted: &'a str,
}

pub(crate) struct AuditOutcome {
    pub report: String,
    pub incomplete: bool,
}

mod audit;
#[cfg(test)]
use audit::parse_pwned_range;

mod import;

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

impl Vault {
    fn ensure_next_entry_id(&mut self) -> Result<(), VaultError> {
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

    fn allocate_entry_id(&mut self) -> Result<usize, VaultError> {
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
}

pub trait VaultAccess {
    fn add_entry(
        &mut self,
        info: PasswordEntry,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, VaultError>;
    fn add_typed_entry(
        &mut self,
        info: TypedEntry,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, VaultError>;
    fn delete_entry(&mut self, id: Target, key_pass: &mut ServerInfo) -> Result<bool, VaultError>;
    fn update_entry_with_limit(
        &mut self,
        update: EntryUpdate,
        key_pass: &mut ServerInfo,
        password_history_limit: usize,
    ) -> Result<bool, VaultError>;
    fn update_typed_entry_with_limit(
        &mut self,
        update: TypedUpdate,
        key_pass: &mut ServerInfo,
        password_history_limit: usize,
    ) -> Result<bool, VaultError>;
    fn lock_vault(&self, key_pass: &mut ServerInfo) -> Result<(), VaultError>;
    fn unlock_vault(&mut self, key_pass: &mut ServerInfo) -> Result<(), VaultError>;
    fn export(&self, path: String, force: bool) -> Result<(), VaultError>;
    fn import_with_options(
        &mut self,
        path: String,
        conflicts: ConflictPolicy,
        preview: bool,
        password_history_limit: usize,
        key_pass: &mut ServerInfo,
    ) -> Result<ImportReport, VaultError>;
}

impl VaultAccess for Option<Vault> {
    fn add_entry(
        &mut self,
        info: PasswordEntry,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, VaultError> {
        match self {
            Some(vlt) => vlt.add_entry(info, key_pass),
            None => Err(VaultError::Locked),
        }
    }
    fn add_typed_entry(
        &mut self,
        info: TypedEntry,
        key_pass: &mut ServerInfo,
    ) -> Result<bool, VaultError> {
        match self {
            Some(vlt) => vlt.add_typed_entry(info, key_pass),
            None => Err(VaultError::Locked),
        }
    }
    fn delete_entry(&mut self, id: Target, key_pass: &mut ServerInfo) -> Result<bool, VaultError> {
        match self {
            Some(vlt) => vlt.delete_entry(id, key_pass),
            None => Err(VaultError::Locked),
        }
    }

    fn update_entry_with_limit(
        &mut self,
        update: EntryUpdate,
        key_pass: &mut ServerInfo,
        password_history_limit: usize,
    ) -> Result<bool, VaultError> {
        match self {
            Some(vault) => vault.update_entry_with_limit(update, key_pass, password_history_limit),
            None => Err(VaultError::Locked),
        }
    }
    fn update_typed_entry_with_limit(
        &mut self,
        update: TypedUpdate,
        key_pass: &mut ServerInfo,
        password_history_limit: usize,
    ) -> Result<bool, VaultError> {
        match self {
            Some(vault) => {
                vault.update_typed_entry_with_limit(update, key_pass, password_history_limit)
            }
            None => Err(VaultError::Locked),
        }
    }

    fn lock_vault(&self, key_pass: &mut ServerInfo) -> Result<(), VaultError> {
        if let Some(vlt) = self {
            vlt.lock_vault(key_pass)?;
        }
        key_pass.zeroize();
        Ok(())
    }
    fn unlock_vault(&mut self, key_pass: &mut ServerInfo) -> Result<(), VaultError> {
        if self.is_some() {
            return Err(
                ("a vault is already unlocked; lock it before unlocking another one".to_string())
                    .into(),
            );
        }
        match crate::vault::unlock_vault(key_pass) {
            Some(vault) => {
                *self = Some(vault);
                Ok(())
            }
            None => {
                Err(("wrong master password, or no vault exists for this key".to_string()).into())
            }
        }
    }
    fn export(&self, path: String, force: bool) -> Result<(), VaultError> {
        if let Some(vlt) = self {
            vlt.export(path, force)
        } else {
            Err(VaultError::Locked)
        }
    }
    fn import_with_options(
        &mut self,
        path: String,
        conflicts: ConflictPolicy,
        preview: bool,
        password_history_limit: usize,
        key_pass: &mut ServerInfo,
    ) -> Result<ImportReport, VaultError> {
        match self {
            Some(vault) => vault.import_with_options(
                path,
                conflicts,
                preview,
                password_history_limit,
                key_pass,
            ),
            None => Err(VaultError::Locked),
        }
    }
}
impl Zeroize for Vault {
    fn zeroize(&mut self) {
        self.entries.zeroize();
        self.metadata.zeroize();
        self.recovery.zeroize();
    }
}
impl Zeroize for VaultEntry {
    fn zeroize(&mut self) {
        self.created.zeroize();
        self.id.zeroize();
        self.modified.zeroize();
        self.name.zeroize();
        self.notes.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.username.zeroize();
        *self = Self::default();
    }
}

#[cfg(test)]
#[path = "vault_tests.rs"]
mod test;

impl Drop for Vault {
    fn drop(&mut self) {
        self.entries.zeroize();
        self.metadata.zeroize();
        self.recovery.zeroize();
    }
}
