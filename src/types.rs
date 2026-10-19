use crate::secret::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum PasswordType {
    Password(String),
    Key(String),
    #[serde(skip)]
    Session {
        encryption_key: [u8; 32],
        salt: [u8; 16],
        kdf: u8,
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    },
}

impl std::fmt::Debug for PasswordType {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => formatter.write_str("Password(<redacted>)"),
            Self::Key(_) => formatter.write_str("Key(<redacted>)"),
            Self::Session { .. } => formatter.write_str("Session(<redacted>)"),
        }
    }
}

impl Zeroize for PasswordEntry {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.url.zeroize();
        self.notes.zeroize();
        self.copy.zeroize();
    }
}

impl Zeroize for TypedEntry {
    fn zeroize(&mut self) {
        self.entry.zeroize();
        self.additional_urls.zeroize();
        self.custom_fields.zeroize();
    }
}

impl Zeroize for UnlockInfo {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.timeout.zeroize();
        self.vault_file.zeroize();
    }
}

impl Zeroize for Target {
    fn zeroize(&mut self) {
        match self {
            Self::Id(id) => id.zeroize(),
            Self::Name(name) | Self::Url(name) => name.zeroize(),
            Self::Vault { key, .. } => key.zeroize(),
        }
    }
}

impl Zeroize for EntryUpdate {
    fn zeroize(&mut self) {
        self.target.zeroize();
        self.update.name.zeroize();
        self.update.username.zeroize();
        self.update.url.zeroize();
        self.update.notes.zeroize();
        self.password.zeroize();
    }
}

impl Zeroize for TypedUpdate {
    fn zeroize(&mut self) {
        self.entry.zeroize();
        self.add_url.zeroize();
        self.remove_url.zeroize();
        self.set_fields.zeroize();
        self.remove_fields.zeroize();
    }
}

impl Zeroize for ServerCommand {
    fn zeroize(&mut self) {
        match self {
            Self::Unlock(info) => info.zeroize(),
            Self::Add { entry, .. } => entry.zeroize(),
            Self::Get { target, .. }
            | Self::GetSecret(target)
            | Self::AuthenticatorData(target)
            | Self::Delete(target)
            | Self::History(target) => target.zeroize(),
            Self::GetField { target, name, .. } => {
                target.zeroize();
                name.zeroize();
            }
            Self::Update(update) => update.zeroize(),
            Self::New(key) | Self::Rekey(key) => key.zeroize(),
            Self::Backup(request) | Self::RestoreBackup(request) => request.zeroize(),
            Self::Import(request) => request.zeroize(),
            Self::Totp(command) => command.zeroize(),
            Self::Duo(command) => command.zeroize(),
            Self::BrowserLogins(origin) | Self::BrowserDuoItems(origin) => origin.zeroize(),
            Self::BrowserLogin { domain, .. } => domain.zeroize(),
            Self::RestorePassword { target, .. } => target.zeroize(),
            _ => {}
        }
    }
}

/// Canonical application operations. Wire tags and field names are explicit.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "operation", content = "arguments", rename_all = "snake_case")]
pub enum ServerCommand {
    Kill,
    Lock(bool),
    Unlock(UnlockInfo),
    Status,
    View(ListOptions),
    BrowserAutofill,
    BrowserAutofillItem(usize),
    Search(SearchFilter),
    Add {
        entry: TypedEntry,
        copy_timeout: u8,
    },
    Get {
        target: Target,
        copy_timeout: u8,
        reveal_secrets: bool,
    },
    GetSecret(Target),
    Delete(Target),
    History(Target),
    RestorePassword {
        target: Target,
        revision: usize,
    },
    Trash,
    RestoreTrash(usize),
    PurgeTrash(Option<usize>),
    Audit(AuditOptions),
    Totp(TotpCommand),
    Backup(BackupRequest),
    RestoreBackup(BackupRequest),
    Update(TypedUpdate),
    Export {
        path: String,
        force: bool,
    },
    Import(ImportRequest),
    New(PasswordType),
    Rekey(PasswordType),
    BrowserLogins(String),
    BrowserLogin {
        domain: String,
        id: usize,
    },
    GetField {
        target: Target,
        name: String,
        copy_timeout: Option<u8>,
    },
    ManagementList(SearchFilter),
    ManagementItem {
        id: usize,
        reveal: bool,
    },
    ManagementCopy {
        id: usize,
        timeout: u8,
    },
    Duo(DuoCommand),
    AuthenticatorData(Target),
    BrowserDuoItems(String),
    OperationStatus(String),
}

impl ServerCommand {
    /// Includes externally visible effects such as HOTP consumption and copies.
    pub fn is_mutation(&self) -> bool {
        !matches!(
            self,
            Self::Status
                | Self::View(_)
                | Self::Search(_)
                | Self::History(_)
                | Self::Trash
                | Self::Audit(_)
                | Self::BrowserAutofill
                | Self::BrowserAutofillItem(_)
                | Self::BrowserLogins(_)
                | Self::BrowserLogin { .. }
                | Self::BrowserDuoItems(_)
                | Self::ManagementList(_)
                | Self::ManagementItem { .. }
                | Self::GetSecret(_)
                | Self::OperationStatus(_)
                | Self::Duo(DuoCommand::Requests { .. })
                | Self::Get {
                    copy_timeout: 0,
                    ..
                }
                | Self::GetField {
                    copy_timeout: None,
                    ..
                }
                | Self::Totp(TotpCommand::Watch {
                    copy_timeout: None,
                    ..
                })
        )
    }
    pub fn extends_unlock(&self) -> bool {
        !matches!(
            self,
            Self::Kill
                | Self::Lock(_)
                | Self::Status
                | Self::OperationStatus(_)
                | Self::BrowserDuoItems(_)
                | Self::Duo(DuoCommand::Requests { .. })
                | Self::Totp(TotpCommand::Watch { .. })
        )
    }
    pub fn revision_target(&self) -> Option<&Target> {
        match self {
            Self::Update(update) => Some(&update.entry.target),
            Self::Delete(target)
            | Self::GetSecret(target)
            | Self::History(target)
            | Self::AuthenticatorData(target)
            | Self::Get { target, .. }
            | Self::GetField { target, .. }
            | Self::RestorePassword { target, .. } => Some(target),
            Self::Totp(
                TotpCommand::Set { target, .. }
                | TotpCommand::Remove { target }
                | TotpCommand::Show { target, .. }
                | TotpCommand::Watch { target, .. }
                | TotpCommand::Duo { target, .. },
            ) => Some(target),
            Self::Duo(
                DuoCommand::Enroll { target, .. }
                | DuoCommand::Requests { target }
                | DuoCommand::Respond { target, .. }
                | DuoCommand::Remove { target },
            ) => Some(target),
            _ => None,
        }
    }
    pub fn target_id(&self) -> Option<usize> {
        let target = match self {
            Self::Update(update) => Some(&update.entry.target),
            Self::Delete(target)
            | Self::GetSecret(target)
            | Self::History(target)
            | Self::AuthenticatorData(target)
            | Self::Get { target, .. }
            | Self::GetField { target, .. }
            | Self::RestorePassword { target, .. } => Some(target),
            _ => None,
        };
        match target {
            Some(Target::Id(id)) => Some(*id),
            _ => match self {
                Self::ManagementItem { id, .. }
                | Self::ManagementCopy { id, .. }
                | Self::BrowserLogin { id, .. }
                | Self::BrowserAutofillItem(id) => Some(*id),
                _ => None,
            },
        }
    }
}

#[derive(
    Serialize, Deserialize, Clone, Default, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop,
)]
pub struct DuoCredentials {
    pub host: String,
    pub akey: String,
    pub pkey: String,
    pub private_key: SecretString,
}

impl std::fmt::Debug for DuoCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DuoCredentials(<redacted>)")
    }
}

#[derive(Serialize, Deserialize, zeroize::Zeroize)]
pub enum DuoCommand {
    Enroll {
        target: Target,
        activation: SecretString,
        mode: Option<OtpMode>,
        replace: bool,
    },
    Requests {
        target: Target,
    },
    Respond {
        target: Target,
        request_id: String,
        fingerprint: String,
        approve: bool,
        code: SecretString,
    },
    Remove {
        target: Target,
    },
}

impl std::fmt::Debug for DuoCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enroll { target, .. } => f
                .debug_struct("DuoEnroll")
                .field("target", target)
                .finish_non_exhaustive(),
            Self::Requests { target } => f
                .debug_struct("DuoRequests")
                .field("target", target)
                .finish(),
            Self::Respond {
                target, approve, ..
            } => f
                .debug_struct("DuoRespond")
                .field("target", target)
                .field("approve", approve)
                .finish_non_exhaustive(),
            Self::Remove { target } => f.debug_struct("DuoRemove").field("target", target).finish(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DuoPushRequest {
    pub id: String,
    pub application: String,
    pub username: String,
    pub location: String,
    pub summary: String,
    pub expires_at: u64,
    pub code_digits: Option<usize>,
    pub unsupported: Option<String>,
    pub fingerprint: String,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ItemKind {
    /// Website or application credentials with username, password, and optional TOTP.
    #[default]
    Login,
    /// Free-form confidential text.
    SecureNote,
    /// Credit, debit, or other payment-card details.
    PaymentCard,
    /// Personal identity or contact information.
    Identity,
    /// Wireless network credentials.
    Wifi,
    /// Software product key and license details.
    SoftwareLicense,
    /// SSH private key or related connection details.
    SshKey,
    /// API token, client secret, or other service credential.
    ApiSecret,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ConflictPolicy {
    /// Leave the existing item unchanged and omit the imported duplicate.
    #[default]
    Skip,
    /// Replace the existing item with the imported item.
    Replace,
    /// Import the duplicate as another item with a distinct name.
    KeepBoth,
}

#[derive(Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CustomField {
    pub name: String,
    pub value: SecretString,
    pub secret: bool,
}

impl std::fmt::Debug for CustomField {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CustomField")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("secret", &self.secret)
            .finish()
    }
}

impl Zeroize for CustomField {
    fn zeroize(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
        self.secret.zeroize();
        *self = Self::default();
    }
}

impl std::fmt::Display for ItemKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::Login => "login",
            Self::SecureNote => "secure-note",
            Self::PaymentCard => "payment-card",
            Self::Identity => "identity",
            Self::Wifi => "wifi",
            Self::SoftwareLicense => "software-license",
            Self::SshKey => "ssh-key",
            Self::ApiSecret => "api-secret",
        };
        formatter.write_str(label)
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SortField {
    /// Stable numeric entry ID.
    #[default]
    Id,
    /// Item name, compared case-insensitively.
    Name,
    /// Creation time.
    Created,
    /// Last modification time.
    Modified,
    /// Age of the current password.
    PasswordAge,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct ListOptions {
    pub kind: Option<ItemKind>,
    pub has_totp: Option<bool>,
    pub weak: bool,
    pub stale_days: Option<u64>,
    pub sort: SortField,
    pub descending: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct AuditOptions {
    /// Report login passwords at least this many days old.
    pub stale_days: Option<u64>,
    /// Check SHA-1 hash prefixes against the Pwned Passwords range API.
    pub check_breaches: bool,
    /// Treat logins without an authenticator as a health finding.
    pub require_totp: bool,
}

#[derive(Serialize, Deserialize)]
pub struct BackupRequest {
    pub path: String,
    pub key_pass: PasswordType,
    pub force: bool,
}

impl std::fmt::Debug for BackupRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BackupRequest")
            .field("path", &self.path)
            .field("key_pass", &"<redacted>")
            .field("force", &self.force)
            .finish()
    }
}

impl Zeroize for BackupRequest {
    fn zeroize(&mut self) {
        self.path.zeroize();
        self.key_pass.zeroize();
        self.force.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
pub struct UnlockInfo {
    pub key: PasswordType,
    pub timeout: u64,
    #[serde(default)]
    pub vault_file: Option<String>,
}

impl std::fmt::Debug for UnlockInfo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnlockInfo")
            .field("vault_file", &self.vault_file)
            .field("key", &"<redacted>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct PasswordEntry {
    pub name: String,
    pub username: Option<String>,
    pub password: SecretString,
    pub url: Option<String>,
    pub notes: Option<SecretString>,
    pub copy: bool,
}

/// Metadata changes supplied by any client. Secret replacement lives in EntryUpdate.
#[derive(Default, Serialize, Deserialize)]
pub struct EntryChanges {
    pub name: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<SecretString>,
}

impl std::fmt::Debug for EntryChanges {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EntryChanges")
            .field("name", &self.name)
            .field("username", &self.username)
            .field("url", &self.url)
            .field("notes", &self.notes.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl std::fmt::Debug for PasswordEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PasswordEntry")
            .field("name", &self.name)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("url", &self.url)
            .field("notes", &self.notes.as_ref().map(|_| "<redacted>"))
            .field("copy", &self.copy)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct TypedEntry {
    pub entry: PasswordEntry,
    pub kind: ItemKind,
    pub additional_urls: Vec<String>,
    pub custom_fields: Vec<CustomField>,
}

impl std::fmt::Debug for TypedEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TypedEntry")
            .field("name", &self.entry.name)
            .field("kind", &self.kind)
            .field("additional_urls", &self.additional_urls)
            .field("custom_field_count", &self.custom_fields.len())
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct SearchFilter {
    pub query: Option<String>,
    pub name: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<SecretString>,
    pub list: ListOptions,
}

#[derive(Serialize, Deserialize)]
pub enum TotpCommand {
    Set {
        target: Target,
        configuration: SecretString,
    },
    Show {
        target: Target,
        copy_timeout: Option<u8>,
    },
    Remove {
        target: Target,
    },
    Duo {
        target: Target,
        activation: SecretString,
        mode: OtpMode,
    },
    Watch {
        target: Target,
        copy_timeout: Option<u8>,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpMode {
    Hotp,
    Totp,
}

impl Zeroize for OtpMode {
    fn zeroize(&mut self) {
        *self = Self::Hotp;
    }
}

impl std::fmt::Debug for TotpCommand {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Set { target, .. } => formatter
                .debug_struct("Set")
                .field("target", target)
                .field("configuration", &"<redacted>")
                .finish(),
            Self::Show {
                target,
                copy_timeout,
            } => formatter
                .debug_struct("Show")
                .field("target", target)
                .field("copy_timeout", copy_timeout)
                .finish(),
            Self::Watch {
                target,
                copy_timeout,
            } => formatter
                .debug_struct("Watch")
                .field("target", target)
                .field("copy_timeout", copy_timeout)
                .finish(),
            Self::Remove { target } => formatter
                .debug_struct("Remove")
                .field("target", target)
                .finish(),
            Self::Duo { target, mode, .. } => formatter
                .debug_struct("Duo")
                .field("target", target)
                .field("mode", mode)
                .field("activation", &"<redacted>")
                .finish(),
        }
    }
}

impl Zeroize for TotpCommand {
    fn zeroize(&mut self) {
        if let Self::Set { configuration, .. } = self {
            configuration.zeroize();
        }
        if let Self::Duo { activation, .. } = self {
            activation.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Target {
    Id(usize),
    Name(String),
    Url(String),
    Vault {
        key: PasswordType,
        keep_key: bool,
        vault_file: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
pub struct EntryUpdate {
    pub target: Target,
    pub update: EntryChanges,
    pub password: Option<SecretString>,
}

impl std::fmt::Debug for EntryUpdate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EntryUpdate")
            .field("target", &self.target)
            .field("changes_name", &self.update.name.is_some())
            .field("changes_username", &self.update.username.is_some())
            .field("changes_password", &self.password.is_some())
            .field("changes_url", &self.update.url.is_some())
            .field("changes_notes", &self.update.notes.is_some())
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct TypedUpdate {
    pub entry: EntryUpdate,
    pub kind: Option<ItemKind>,
    pub add_url: Vec<String>,
    pub remove_url: Vec<String>,
    pub clear_urls: bool,
    pub set_fields: Vec<CustomField>,
    pub remove_fields: Vec<String>,
    pub clear_fields: bool,
}

impl std::fmt::Debug for TypedUpdate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TypedUpdate")
            .field("target", &self.entry.target)
            .field("kind", &self.kind)
            .field("add_url", &self.add_url)
            .field("remove_url", &self.remove_url)
            .field("clear_urls", &self.clear_urls)
            .field("custom_field_count", &self.set_fields.len())
            .field("remove_fields", &self.remove_fields)
            .field("clear_fields", &self.clear_fields)
            .field(
                "secret",
                &self.entry.password.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}
#[derive(Serialize, Deserialize)]
pub struct ImportRequest {
    pub path: String,
    pub new: bool,
    pub key_pass: Option<PasswordType>,
    pub preview: bool,
    pub conflicts: ConflictPolicy,
    pub password_history_limit: usize,
}

impl std::fmt::Debug for ImportRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ImportRequest")
            .field("path", &self.path)
            .field("new", &self.new)
            .field("key_pass", &"<redacted>")
            .field("preview", &self.preview)
            .field("conflicts", &self.conflicts)
            .field("password_history_limit", &self.password_history_limit)
            .finish()
    }
}

impl Zeroize for ImportRequest {
    fn zeroize(&mut self) {
        self.path.zeroize();
        self.key_pass.zeroize();
        self.password_history_limit.zeroize();
    }
}

impl Zeroize for PasswordType {
    fn zeroize(&mut self) {
        match self {
            PasswordType::Key(k) => {
                k.zeroize();
            }
            PasswordType::Password(p) => {
                p.zeroize();
            }
            PasswordType::Session {
                encryption_key,
                salt,
                kdf,
                memory_kib,
                iterations,
                parallelism,
            } => {
                encryption_key.zeroize();
                salt.zeroize();
                kdf.zeroize();
                memory_kib.zeroize();
                iterations.zeroize();
                parallelism.zeroize();
            }
        }
    }
}

impl Drop for PasswordType {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    #[test]
    fn secret_commands_redact_debug_but_preserve_explicit_serialization() {
        let secret = " padded\ncommand-secret\n ";
        for command in [
            ServerCommand::Totp(TotpCommand::Set {
                target: Target::Id(1),
                configuration: secret.into(),
            }),
            ServerCommand::Totp(TotpCommand::Duo {
                target: Target::Id(1),
                activation: secret.into(),
                mode: OtpMode::Hotp,
            }),
            ServerCommand::Duo(DuoCommand::Respond {
                target: Target::Id(1),
                request_id: "request".into(),
                fingerprint: "a".repeat(128),
                approve: true,
                code: secret.into(),
            }),
        ] {
            assert!(!format!("{command:?}").contains("command-secret"));
            let encoded = serde_json::to_string(&command).unwrap();
            assert!(encoded.contains("command-secret"));
            let mut decoded: ServerCommand = serde_json::from_str(&encoded).unwrap();
            decoded.zeroize();
            assert!(
                !serde_json::to_string(&decoded)
                    .unwrap()
                    .contains("command-secret")
            );
        }
    }
    #[test]
    fn metadata_secret_updates_have_one_canonical_named_representation() {
        let command = ServerCommand::Update(TypedUpdate {
            entry: EntryUpdate {
                target: Target::Id(7),
                update: EntryChanges {
                    notes: Some("private note".into()),
                    ..Default::default()
                },
                password: Some("".into()),
            },
            kind: None,
            add_url: vec![],
            remove_url: vec![],
            clear_urls: false,
            set_fields: vec![],
            remove_fields: vec![],
            clear_fields: false,
        });
        let wire = serde_json::to_value(&command).unwrap();
        assert_eq!(wire["operation"], "update");
        assert_eq!(wire["arguments"]["entry"]["password"], "");
        assert!(
            wire["arguments"]["entry"]["update"]
                .get("generate_password")
                .is_none()
        );
        assert!(!format!("{command:?}").contains("private note"));
    }
}
