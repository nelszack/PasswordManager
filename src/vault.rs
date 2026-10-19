use crate::secret::SecretString;
use crate::{
    encryption::{
        decrypt_file, try_encrypt_file_in_place, try_gen_master_key, validate_new_password,
    },
    file::{data_dir, key_file_path, new_key_file_path, set_private_perms, sync_parent},
    types::{
        AuditOptions, ConflictPolicy, CustomField, DuoCredentials, EntryChanges, EntryUpdate,
        ItemKind, ListOptions, PasswordEntry, PasswordType, SearchFilter, SortField, Target,
        TypedEntry, TypedUpdate,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha1::{Digest, Sha1};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs,
    io::{Read, Write},
    path::Path,
};
use tempfile::NamedTempFile;
use totp_rs::{Builder as TotpBuilder, Secret as TotpSecret, Totp, TotpError};
use zeroize::{Zeroize, Zeroizing};

mod session;
pub(crate) use session::available;
pub use session::{VaultCredentials, VaultSession};
mod error;
pub use error::VaultError;
mod duo;
pub(crate) use duo::{DuoPollResult, PreparedDuoEnrollment, PreparedDuoPoll};
mod recovery;
mod totp;
pub use totp::AuthenticatorCode;

mod browser;
mod management;
pub use browser::{AutofillItem, BrowserLogin};
pub use management::{
    HistoryPage, ItemDetail, ItemField, ItemPage, ItemSummary, TrashPage, TrashSummary,
};
mod query;
use browser::hostname;
#[cfg(test)]
use browser::hosts_match;
mod backup;
pub(crate) use backup::restore_encrypted_backup;
mod entries;
mod export;

mod persistence;
pub use persistence::VaultStore;
pub(crate) use persistence::unlock_selected_vault;
#[cfg(test)]
pub(crate) use persistence::with_write_fault;
pub(crate) use persistence::{create_vault, delete_vault};
pub use persistence::{list_vaults, validate_vault_filename};
use persistence::{persist_private_file, write_vault, write_vault_with_key};
mod transaction;
use transaction::TransactionScope;

/// Borrowed domain records; rendering does not require cloning vault secrets.
pub struct EntryView<'a> {
    pub entry: &'a VaultEntry,
    pub metadata: Option<&'a EntryMetadata>,
    pub has_totp: bool,
    pub urls: Vec<&'a str>,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLabel {
    pub id: usize,
    pub name: String,
    pub username: Option<String>,
    pub password_changed: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
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

mod import;

/// A fixed-width, nonzero identity in the durable domain. Public adapters perform
/// checked conversion to their presentation ID; zero is never a valid item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u64", into = "u64")]
pub struct ItemId(u64);
const MAX_ITEM_ID: u64 = 9_007_199_254_740_991;
impl TryFrom<u64> for ItemId {
    type Error = &'static str;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value == 0 || value > MAX_ITEM_ID {
            Err("item ID must be a positive safe integer")
        } else {
            Ok(Self(value))
        }
    }
}
impl From<ItemId> for u64 {
    fn from(value: ItemId) -> u64 {
        value.0
    }
}
impl ItemId {
    fn from_public(value: usize) -> Result<Self, VaultError> {
        Self::try_from(
            u64::try_from(value)
                .map_err(|_| VaultError::InvalidInput("item ID is out of range".into()))?,
        )
        .map_err(|e| VaultError::InvalidInput(e.into()))
    }
    fn public(self) -> Result<usize, VaultError> {
        usize::try_from(self.0).map_err(|_| {
            VaultError::Validation("item ID exceeds this platform's supported range".into())
        })
    }
}

/// Validated UTC timestamp, kept in canonical RFC3339 form for borrowed views.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct Timestamp(String);
impl Timestamp {
    pub fn now() -> Self {
        Self(chrono::Utc::now().to_rfc3339())
    }
    pub fn parse(value: &str) -> Result<Self, VaultError> {
        parse_entry_timestamp(value)
            .map(|v| Self(v.to_rfc3339()))
            .ok_or_else(|| VaultError::Validation("invalid item timestamp".into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl Default for Timestamp {
    fn default() -> Self {
        Self("1970-01-01T00:00:00+00:00".into())
    }
}
impl std::ops::Deref for Timestamp {
    type Target = String;
    fn deref(&self) -> &String {
        &self.0
    }
}
impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
#[cfg(test)]
impl From<String> for Timestamp {
    fn from(value: String) -> Self {
        Self::parse(&value).expect("valid fixture timestamp")
    }
}
#[cfg(test)]
impl From<&str> for Timestamp {
    fn from(value: &str) -> Self {
        Self::parse(value).expect("valid fixture timestamp")
    }
}
impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
impl Zeroize for Timestamp {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Serialize, Deserialize, Default, PartialEq, Clone)]
pub struct VaultEntry {
    pub id: usize,
    pub name: String,
    pub username: Option<String>,
    pub password: SecretString,
    pub url: Option<String>,
    pub notes: Option<SecretString>,
    pub created: Timestamp,
    pub modified: Timestamp,
}
impl std::fmt::Debug for VaultEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultEntry")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("notes", &self.notes.as_ref().map(|_| "<redacted>"))
            .field("created", &self.created)
            .field("modified", &self.modified)
            .finish()
    }
}
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone, zeroize::Zeroize)]
pub struct PasswordRevision {
    pub password: SecretString,
    pub changed: Timestamp,
}
#[derive(Serialize, Deserialize, Debug, Default, PartialEq, Clone)]
pub struct EntryMetadata {
    pub kind: ItemKind,
    pub additional_urls: Vec<String>,
    pub password_changed: Option<Timestamp>,
    pub custom_fields: Vec<CustomField>,
}
impl Zeroize for EntryMetadata {
    fn zeroize(&mut self) {
        self.additional_urls.zeroize();
        self.password_changed.zeroize();
        self.custom_fields.zeroize();
    }
}
#[derive(
    Serialize, Deserialize, Default, PartialEq, Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop,
)]
pub struct DuoRecord {
    pub credentials: DuoCredentials,
    #[serde(skip)]
    pub(crate) review_key: Option<[u8; 32]>,
}
impl std::fmt::Debug for DuoRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DuoRecord").finish_non_exhaustive()
    }
}

/// Validated at ingestion; durable text is a transport representation only.
#[derive(Debug, Clone, PartialEq)]
struct Authenticator {
    configuration: SecretString,
    state: AuthenticatorState,
}
#[derive(Debug, Clone, PartialEq)]
enum AuthenticatorState {
    Totp(Totp),
    Hotp { generator: Totp, counter: u64 },
}
impl Authenticator {
    fn parse(value: &str) -> Result<Self, VaultError> {
        let (configuration, _) = totp::normalize_totp_configuration(value)?;
        let mut configuration = Zeroizing::new(configuration);
        let state = if totp::is_hotp_uri(&configuration) {
            let (generator, counter) = totp::parse_hotp_configuration(&configuration)?;
            AuthenticatorState::Hotp { generator, counter }
        } else {
            AuthenticatorState::Totp(totp::parse_totp_configuration(&configuration)?)
        };
        Ok(Self {
            configuration: std::mem::take(&mut *configuration).into(),
            state,
        })
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum Lifecycle {
    Active,
    Trashed { deleted_at: Timestamp },
}
#[derive(Debug, Clone, PartialEq)]
struct Item {
    entry: VaultEntry,
    revision: u64,
    metadata: EntryMetadata,
    history: Vec<PasswordRevision>,
    authenticator: Option<Authenticator>,
    duo: Option<DuoRecord>,
    lifecycle: Lifecycle,
}
impl Item {
    fn active(&self) -> bool {
        matches!(self.lifecycle, Lifecycle::Active)
    }
    fn new(entry: VaultEntry, metadata: EntryMetadata) -> Self {
        Self {
            entry,
            revision: 0,
            metadata,
            history: Vec::new(),
            authenticator: None,
            duo: None,
            lifecycle: Lifecycle::Active,
        }
    }
}
/// Pure domain state: no paths, keys, runtime handles, or storage operations.
#[derive(Debug, PartialEq)]
#[cfg_attr(test, derive(Clone))]
pub struct VaultData {
    items: BTreeMap<ItemId, Item>,
    vault_id: [u8; 16],
    next_item_id: u64,
    revision: u64,
}
impl Default for VaultData {
    fn default() -> Self {
        Self {
            items: BTreeMap::new(),
            vault_id: [0; 16],
            next_item_id: 1,
            revision: 0,
        }
    }
}

#[derive(Default, PartialEq, Clone)]
pub struct VaultMetadata {
    pub filename: String,
    pub(crate) duo_session: Option<[u8; 32]>,
}
impl std::fmt::Debug for VaultMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultMetadata")
            .field("filename", &self.filename)
            .finish_non_exhaustive()
    }
}
impl Zeroize for VaultMetadata {
    fn zeroize(&mut self) {
        self.filename.zeroize();
        self.duo_session.zeroize();
    }
}
impl Drop for VaultMetadata {
    fn drop(&mut self) {
        self.zeroize();
    }
}
/// Runtime handle. Only the store knows the durable location; no runtime fields
/// are part of VaultDocument. A default handle is deliberately not writable.
#[derive(Debug, PartialEq)]
#[cfg_attr(test, derive(Clone))]
pub struct Vault {
    data: VaultData,
    store: VaultStore,
    pub metadata: VaultMetadata,
}
impl Default for Vault {
    fn default() -> Self {
        Self {
            data: VaultData::default(),
            store: VaultStore::Detached,
            metadata: VaultMetadata::default(),
        }
    }
}
impl Vault {
    pub fn memory() -> Self {
        Self {
            data: VaultData {
                vault_id: rand::random(),
                ..VaultData::default()
            },
            store: VaultStore::Memory,
            ..Self::default()
        }
    }
    fn item(&self, id: usize) -> Option<&Item> {
        self.data.items.get(&ItemId::from_public(id).ok()?)
    }
    fn item_mut(&mut self, id: usize) -> Option<&mut Item> {
        self.data.items.get_mut(&ItemId::from_public(id).ok()?)
    }
    fn active_items(&self) -> impl Iterator<Item = &Item> {
        self.data.items.values().filter(|i| i.active())
    }
    fn active_entries(&self) -> impl Iterator<Item = &VaultEntry> {
        self.active_items().map(|i| &i.entry)
    }
    fn entry_id(&self, target: &Target) -> Option<usize> {
        match target {
            Target::Id(id) => self.item(*id).filter(|i| i.active()).map(|i| i.entry.id),
            Target::Name(name) => self
                .active_entries()
                .find(|e| e.name == *name)
                .map(|e| e.id),
            _ => None,
        }
    }
    fn metadata(&self, id: usize) -> Option<&EntryMetadata> {
        self.item(id).map(|i| &i.metadata)
    }
    fn item_kind(&self, id: usize) -> ItemKind {
        self.metadata(id).map_or(ItemKind::Login, |m| m.kind)
    }
    fn all_urls<'a>(&'a self, entry: &'a VaultEntry) -> impl Iterator<Item = &'a str> {
        entry.url.as_deref().into_iter().chain(
            self.metadata(entry.id)
                .into_iter()
                .flat_map(|m| m.additional_urls.iter().map(String::as_str)),
        )
    }
    fn custom_fields(&self, id: usize) -> &[CustomField] {
        self.metadata(id)
            .map_or(&[], |m| m.custom_fields.as_slice())
    }
    pub fn revision(&self, id: usize) -> Option<u64> {
        self.item(id).map(|i| i.revision)
    }
    pub fn item_revision(&self, id: usize) -> Option<u64> {
        self.revision(id)
    }
    pub fn vault_id(&self) -> [u8; 16] {
        self.data.vault_id
    }
    pub fn vault_revision(&self) -> u64 {
        self.data.revision
    }
    pub fn check_revision(&self, id: usize, expected: u64) -> Result<(), VaultError> {
        let revision = self
            .revision(id)
            .ok_or_else(|| VaultError::NotFound("item not found".into()))?;
        if revision != expected {
            Err(VaultError::Conflict(format!(
                "item revision changed: expected {expected}, current {revision}"
            )))
        } else {
            Ok(())
        }
    }
    fn view(&self, item: &Item) -> EntryView<'_> {
        self.view_id(item.entry.id).expect("item is part of vault")
    }
    fn view_id(&self, id: usize) -> Option<EntryView<'_>> {
        let item = self.item(id)?;
        Some(EntryView {
            entry: &item.entry,
            metadata: Some(&item.metadata),
            has_totp: item.authenticator.is_some(),
            urls: self.all_urls(&item.entry).collect(),
        })
    }
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
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
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
    password: SecretString,
    url: Option<String>,
    notes: Option<SecretString>,
    created: Timestamp,
    modified: Timestamp,
    #[serde(rename = "type")]
    kind: ItemKind,
    additional_urls: Vec<String>,
    custom_fields: Vec<CustomField>,
    password_changed: Option<Timestamp>,
    password_history: Vec<PortableRevision>,
    totp: Option<SecretString>,
    #[serde(default)]
    duo: Option<DuoCredentials>,
}

#[derive(Serialize, Deserialize)]
struct PortableRevision {
    password: SecretString,
    changed: Timestamp,
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
        self.duo.zeroize();
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
    password_changed: Option<Timestamp>,
    password_history: Vec<PortableRevision>,
    totp: Option<SecretString>,
    duo: Option<DuoCredentials>,
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
        self.duo.zeroize();
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
            duo: None,
        }
    }
}

const BACKUP_MAGIC: &[u8; 8] = b"PMBACKUP";
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
    let Some(threshold) = i64::try_from(days)
        .ok()
        .and_then(chrono::Duration::try_days)
    else {
        // Such a threshold exceeds every representable timestamp's age.
        return false;
    };
    now.signed_duration_since(changed) >= threshold
}

impl Zeroize for VaultEntry {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.notes.zeroize();
        self.created.zeroize();
        self.modified.zeroize();
        self.id.zeroize();
    }
}
impl Zeroize for Vault {
    fn zeroize(&mut self) {
        self.data.items.clear();
        self.metadata.zeroize();
        self.data.next_item_id = 1;
        self.data.revision = 0;
    }
}
#[cfg(test)]
#[path = "vault_tests.rs"]
mod test;
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_imports(text: &str) {
    for items in [
        import::import_csv(text, "synthetic.csv"),
        import::import_json(text, "synthetic.json"),
    ]
    .into_iter()
    .flatten()
    {
        drop(items);
    }
}

#[cfg(test)]
impl Vault {
    pub(crate) fn from_entries(entries: Vec<VaultEntry>, filename: Option<String>) -> Self {
        let mut vault = Self::memory();
        for mut entry in entries {
            if entry.id == 0 {
                entry.id = vault.data.next_item_id as usize;
            }
            let id = ItemId::from_public(entry.id).expect("valid fixture ID");
            vault.data.next_item_id = vault.data.next_item_id.max(id.0 + 1);
            let mut item = Item::new(entry, EntryMetadata::default());
            item.revision = 1;
            vault.data.items.insert(id, item);
        }
        if let Some(filename) = filename {
            vault.metadata.filename = filename.clone();
            vault.store = VaultStore::File {
                directory: data_dir(),
                filename,
            };
        }
        vault
    }
    pub(crate) fn set_test_totp(&mut self, id: usize, value: &str) {
        self.item_mut(id).unwrap().authenticator =
            Some(Authenticator::parse(value).expect("valid fixture authenticator"));
    }
    pub(crate) fn set_test_metadata(
        &mut self,
        id: usize,
        kind: ItemKind,
        urls: Vec<String>,
        fields: Vec<CustomField>,
    ) {
        self.item_mut(id).unwrap().metadata = EntryMetadata {
            kind,
            additional_urls: urls,
            password_changed: None,
            custom_fields: fields,
        };
    }
    pub(crate) fn set_test_duo(&mut self, id: usize, credentials: DuoCredentials) {
        self.item_mut(id).unwrap().duo = Some(DuoRecord {
            credentials,
            review_key: None,
        });
    }
}
