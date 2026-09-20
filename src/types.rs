use clap::{Args, ValueEnum};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum PasswordType {
    Password(String),
    Key(String),
}

impl std::fmt::Debug for PasswordType {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(_) => formatter.write_str("Password(<redacted>)"),
            Self::Key(_) => formatter.write_str("Key(<redacted>)"),
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
            Self::Add(entry) => entry.zeroize(),
            Self::AddTyped(entry) | Self::AddTypedWithOptions { entry, .. } => entry.zeroize(),
            Self::Get(target)
            | Self::GetSecret(target)
            | Self::Delete(target)
            | Self::History(target) => target.zeroize(),
            Self::GetWithOptions {
                target,
                copy_timeout,
            } => {
                target.zeroize();
                copy_timeout.zeroize();
            }
            Self::RestorePassword { target, revision } => {
                target.zeroize();
                revision.zeroize();
            }
            Self::Totp(command) => command.zeroize(),
            Self::Backup(request) | Self::RestoreBackup(request) => request.zeroize(),
            Self::Update(update) => update.zeroize(),
            Self::UpdateTyped(update) => update.zeroize(),
            Self::Export(path) => path.zeroize(),
            Self::Import(request) => request.zeroize(),
            Self::New(key) | Self::Rekey(key) => key.zeroize(),
            Self::Search(filter) => {
                filter.query.zeroize();
                filter.name.zeroize();
                filter.username.zeroize();
                filter.url.zeroize();
                filter.notes.zeroize();
            }
            Self::Kill
            | Self::Lock(_)
            | Self::Status
            | Self::View(_)
            | Self::BrowserAutofill
            | Self::BrowserAutofillItem(_)
            | Self::Trash
            | Self::RestoreTrash(_)
            | Self::PurgeTrash(_)
            | Self::Audit(_) => {}
        }
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub enum ServerCommand {
    Kill,
    Lock(bool),
    Unlock(UnlockInfo),
    Status,
    View(ListOptions),
    BrowserAutofill,
    BrowserAutofillItem(usize),
    Search(SearchFilter),
    Add(PasswordEntry),
    AddTyped(TypedEntry),
    AddTypedWithOptions { entry: TypedEntry, copy_timeout: u8 },
    Get(Target),
    GetWithOptions { target: Target, copy_timeout: u8 },
    GetSecret(Target),
    Delete(Target),
    History(Target),
    RestorePassword { target: Target, revision: usize },
    Trash,
    RestoreTrash(usize),
    PurgeTrash(Option<usize>),
    Audit(AuditOptions),
    Totp(TotpCommand),
    Backup(BackupRequest),
    RestoreBackup(BackupRequest),
    Update(EntryUpdate),
    UpdateTyped(TypedUpdate),
    Export(String),
    Import(ImportRequest),
    New(PasswordType),
    Rekey(PasswordType),
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Default, PartialEq, Eq, ValueEnum)]
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

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Default, PartialEq, Eq, ValueEnum)]
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
    pub value: String,
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

#[derive(Clone, Copy, Serialize, Deserialize, Debug, Default, PartialEq, Eq, ValueEnum)]
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
}

impl std::fmt::Debug for UnlockInfo {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnlockInfo")
            .field("key", &"<redacted>")
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct PasswordEntry {
    pub name: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub copy: bool,
}

#[derive(Serialize, Deserialize, Debug, Args)]
pub struct UpdateArgs {
    /// Replace the item's display name.
    #[arg(long)]
    pub name: Option<String>,
    /// Replace the username or secondary identifier; an empty value clears it.
    #[arg(long)]
    pub username: Option<String>,
    /// Prompt for and replace the primary secret.
    #[arg(long, default_value_t = false)]
    pub password: bool,
    /// Generate the replacement secret instead of prompting for it.
    #[arg(
        long = "generate-password",
        default_value_t = false,
        requires = "password"
    )]
    pub generate_password: bool,
    /// Replace the primary URL.
    #[arg(long)]
    pub url: Option<String>,
    /// Replace the notes text; an empty value clears it.
    #[arg(long)]
    pub notes: Option<String>,
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
    pub notes: Option<String>,
    pub list: ListOptions,
}

#[derive(Serialize, Deserialize)]
pub enum TotpCommand {
    Set {
        target: Target,
        configuration: String,
    },
    Show {
        target: Target,
        copy_timeout: Option<u8>,
    },
    Remove {
        target: Target,
    },
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
            Self::Remove { target } => formatter
                .debug_struct("Remove")
                .field("target", target)
                .finish(),
        }
    }
}

impl Zeroize for TotpCommand {
    fn zeroize(&mut self) {
        if let Self::Set { configuration, .. } = self {
            configuration.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Target {
    Id(usize),
    Name(String),
    Url(String),
    Vault { key: PasswordType, keep_key: bool },
}

#[derive(Serialize, Deserialize)]
pub struct EntryUpdate {
    pub target: Target,
    pub update: UpdateArgs,
    pub password: Option<String>,
}

impl std::fmt::Debug for EntryUpdate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EntryUpdate")
            .field("target", &self.target)
            .field("changes_name", &self.update.name.is_some())
            .field("changes_username", &self.update.username.is_some())
            .field("changes_password", &self.update.password)
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sensitive_command_debug_output_is_redacted() {
        let backup_secret = "backup-password-that-must-not-leak";
        let backup = BackupRequest {
            path: "archive.pmbackup".into(),
            key_pass: PasswordType::Password(backup_secret.into()),
            force: false,
        };
        let backup_debug = format!("{backup:?}");
        assert!(backup_debug.contains("<redacted>"));
        assert!(!backup_debug.contains(backup_secret));

        let totp_secret = "JBSWY3DPEHPK3PXP";
        let totp = TotpCommand::Set {
            target: Target::Id(1),
            configuration: totp_secret.into(),
        };
        let totp_debug = format!("{totp:?}");
        assert!(totp_debug.contains("<redacted>"));
        assert!(!totp_debug.contains(totp_secret));

        let item_secret = "typed-item-secret-that-must-not-leak";
        let custom_secret = "custom-field-secret-that-must-not-leak";
        let item = TypedEntry {
            entry: PasswordEntry {
                name: "API credential".into(),
                username: None,
                password: item_secret.into(),
                url: None,
                notes: None,
                copy: false,
            },
            kind: ItemKind::ApiSecret,
            additional_urls: Vec::new(),
            custom_fields: vec![CustomField {
                name: "token".into(),
                value: custom_secret.into(),
                secret: true,
            }],
        };
        let item_debug = format!("{item:?}");
        assert!(item_debug.contains("<redacted>"));
        assert!(!item_debug.contains(item_secret));
        assert!(!item_debug.contains(custom_secret));

        let master_secret = "master-password-that-must-not-leak";
        let unlock = ServerCommand::Unlock(UnlockInfo {
            key: PasswordType::Password(master_secret.into()),
            timeout: 60,
        });
        assert!(!format!("{unlock:?}").contains(master_secret));

        let update_secret = "updated-password-that-must-not-leak";
        let update = ServerCommand::Update(EntryUpdate {
            target: Target::Id(1),
            update: UpdateArgs {
                name: None,
                username: None,
                password: true,
                generate_password: false,
                url: None,
                notes: None,
            },
            password: Some(update_secret.into()),
        });
        assert!(!format!("{update:?}").contains(update_secret));

        let import_secret = "import-password-that-must-not-leak";
        let import = ServerCommand::Import(ImportRequest {
            path: "input.csv".into(),
            new: true,
            key_pass: Some(PasswordType::Password(import_secret.into())),
            preview: false,
            conflicts: ConflictPolicy::Skip,
            password_history_limit: 10,
        });
        assert!(!format!("{import:?}").contains(import_secret));
    }

    #[test]
    fn sensitive_commands_are_zeroized_after_transport_encoding() {
        let mut command = ServerCommand::Unlock(UnlockInfo {
            key: PasswordType::Password("master-secret".into()),
            timeout: 60,
        });
        command.zeroize();
        assert!(matches!(
            command,
            ServerCommand::Unlock(UnlockInfo {
                key: PasswordType::Password(ref password),
                timeout: 0,
            }) if password.is_empty()
        ));

        let mut command = ServerCommand::Add(PasswordEntry {
            name: "service".into(),
            username: Some("alice".into()),
            password: "entry-secret".into(),
            url: Some("example.com".into()),
            notes: Some("private note".into()),
            copy: true,
        });
        command.zeroize();
        assert!(matches!(
            command,
            ServerCommand::Add(PasswordEntry {
                ref password,
                ref notes,
                ..
            }) if password.is_empty() && notes.as_deref().is_none_or(str::is_empty)
        ));
    }
}
