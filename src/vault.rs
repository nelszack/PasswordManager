#[cfg(test)]
use crate::encryption::{PRODUCTION_KDF_PARAMETERS, try_encrypt_file, with_test_kdf_parameters};
use crate::{
    encryption::{
        decrypt_file, try_encrypt_file_in_place, try_gen_master_key, validate_new_password,
    },
    file::{
        data_dir, file_exists, key_file_path, new_key_file_path, set_private_perms, sync_parent,
    },
    types::{
        AuditOptions, ConflictPolicy, CustomField, EntryChanges, EntryUpdate, ItemKind,
        ListOptions, PasswordEntry, PasswordType, SearchFilter, SortField, Target, TypedEntry,
        TypedUpdate,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha1::{Digest, Sha1};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{Read, Write},
    path::Path,
};
use tempfile::NamedTempFile;
use totp_rs::{Builder as TotpBuilder, Secret as TotpSecret, Totp, TotpError};
use zeroize::{Zeroize, Zeroizing};

mod session;
#[cfg(test)]
use VaultCredentials as ServerInfo;
pub(crate) use session::available;
pub use session::{VaultCredentials, VaultSession};
mod error;
pub use error::VaultError;
mod recovery;
mod totp;

mod browser;
mod management;
mod query;
use backup::validate_backup_vault;
use browser::hostname;
#[cfg(test)]
use browser::hosts_match;
mod backup;
pub(crate) use backup::restore_encrypted_backup;
mod entries;
mod export;

mod persistence;
pub(crate) use persistence::unlock_selected_vault;
pub(crate) use persistence::{create_vault, delete_vault};
#[cfg(test)]
use persistence::{find_vault, unlock_vault};
pub use persistence::{list_vaults, validate_vault_filename};
use persistence::{
    lookup_vault, persist_private_file, random_vault_filename, write_vault, write_vault_with_key,
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
    pub report: AuditReport,
    pub incomplete: bool,
}

/// Public audit findings contain labels and counts, never password hashes or secrets.
#[derive(Debug, Serialize)]
pub struct AuditLabel {
    pub id: usize,
    pub name: String,
    pub username: Option<String>,
    pub password_changed: String,
}
#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub total: usize,
    pub healthy: usize,
    pub score: usize,
    pub weak: Vec<AuditLabel>,
    pub reused: Vec<Vec<AuditLabel>>,
    pub duplicates: Vec<Vec<AuditLabel>>,
    pub stale: Vec<AuditLabel>,
    pub missing_totp: Vec<AuditLabel>,
    pub breached: Vec<(AuditLabel, u64)>,
    pub breach_error: Option<String>,
    pub unchecked: Vec<AuditLabel>,
}
impl AuditEntrySnapshot {
    fn label(&self) -> AuditLabel {
        AuditLabel {
            id: self.id,
            name: self.name.clone(),
            username: self.username.clone(),
            password_changed: self.password_changed.clone(),
        }
    }
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
    pub unsupported: usize,
    pub loss_count: usize,
    /// Bounded, secret-free descriptions indexed by source row/item.
    pub losses: Vec<String>,
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
        )?;
        if self.unsupported > 0 || self.loss_count > 0 {
            write!(
                formatter,
                " {} unsupported items, {} data-loss warnings.",
                self.unsupported, self.loss_count
            )?;
            for loss in &self.losses {
                write!(formatter, "\nWarning: {loss}")?;
            }
            if self.loss_count > self.losses.len() {
                write!(
                    formatter,
                    "\n{} additional warnings omitted.",
                    self.loss_count - self.losses.len()
                )?;
            }
        }
        Ok(())
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

fn parse_entry_timestamp(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .or_else(|_| chrono::DateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f %:z"))
        .ok()
        .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
}

fn password_is_stale_at(changed: &str, days: u64, now: chrono::DateTime<chrono::Utc>) -> bool {
    let Some(changed) = parse_entry_timestamp(changed) else {
        return false;
    };
    now.signed_duration_since(changed)
        >= chrono::Duration::days(i64::try_from(days).unwrap_or(i64::MAX))
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
        self.allocate_validated_entry_id()
    }

    // Bulk imports validate the counter once inside the rollback transaction.
    fn allocate_validated_entry_id(&mut self) -> Result<usize, VaultError> {
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

    #[cfg(test)]
    fn password_changed<'a>(&'a self, entry: &'a VaultEntry) -> &'a str {
        self.metadata(entry.id)
            .and_then(|record| record.password_changed.as_deref())
            .unwrap_or(&entry.created)
    }

    #[cfg(test)]
    fn password_is_stale(&self, entry: &VaultEntry, days: u64) -> bool {
        let changed = self.password_changed(entry);
        password_is_stale_at(changed, days, chrono::Utc::now())
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

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_imports(text: &str) {
    for mut items in [
        import::import_csv(text, "synthetic.csv"),
        import::import_json(text, "synthetic.json"),
    ]
    .into_iter()
    .flatten()
    {
        items.zeroize();
    }
}
