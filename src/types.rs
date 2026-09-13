use crate::cli::UpdateArgs;
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
    View,
    Search(SearchFilter),
    Add(PasswordEntry),
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
    Export(String),
    Import(ImportRequest),
    New(PasswordType),
    Rekey(PasswordType),
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

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct SearchFilter {
    pub query: Option<String>,
    pub name: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub notes: Option<String>,
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
    }
}
