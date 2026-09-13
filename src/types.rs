use crate::cli::UpdateArgs;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub enum PasswordType {
    Password(String),
    Key(String),
}
#[derive(Serialize, Deserialize, Debug)]
pub enum ServerCommand {
    Kill,
    Lock(bool),
    Unlock(UnlockInfo),
    Status,
    View(ListOptions),
    Search(SearchFilter),
    Add(PasswordEntry),
    AddTyped(TypedEntry),
    Get(Target),
    Delete(Target),
    History(Target),
    RestorePassword { target: Target, revision: usize },
    Trash,
    RestoreTrash(usize),
    PurgeTrash(Option<usize>),
    Audit,
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
    #[default]
    Login,
    SecureNote,
    PaymentCard,
    Identity,
    Wifi,
    SoftwareLicense,
    SshKey,
    ApiSecret,
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
    #[default]
    Id,
    Name,
    Created,
    Modified,
    PasswordAge,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct ListOptions {
    pub kind: Option<ItemKind>,
    pub has_totp: Option<bool>,
    pub weak: bool,
    pub sort: SortField,
    pub descending: bool,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct UnlockInfo {
    pub key: PasswordType,
    pub timeout: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PasswordEntry {
    pub name: String,
    pub username: Option<String>,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub copy: bool,
}

#[derive(Serialize, Deserialize)]
pub struct TypedEntry {
    pub entry: PasswordEntry,
    pub kind: ItemKind,
    pub additional_urls: Vec<String>,
}

impl std::fmt::Debug for TypedEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TypedEntry")
            .field("name", &self.entry.name)
            .field("kind", &self.kind)
            .field("additional_urls", &self.additional_urls)
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
    Vault(PasswordType),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EntryUpdate {
    pub target: Target,
    pub update: UpdateArgs,
    pub password: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct TypedUpdate {
    pub entry: EntryUpdate,
    pub kind: Option<ItemKind>,
    pub add_url: Vec<String>,
    pub remove_url: Vec<String>,
    pub clear_urls: bool,
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
            .field(
                "secret",
                &self.entry.password.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ImportRequest {
    pub path: String,
    pub new: bool,
    pub key_pass: PasswordType,
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
        };
        let item_debug = format!("{item:?}");
        assert!(item_debug.contains("<redacted>"));
        assert!(!item_debug.contains(item_secret));
    }
}
