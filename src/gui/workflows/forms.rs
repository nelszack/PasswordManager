//! Inputs owned by each desktop tool; results and request lifetimes stay in State.
use super::*;

pub struct FilesForm {
    pub file_operation: FileOperation,
    pub path: String,
    pub force: bool,
    pub import_new: bool,
    pub policy: Policy,
}
impl Default for FilesForm {
    fn default() -> Self {
        Self {
            file_operation: FileOperation::Backup,
            path: String::new(),
            force: false,
            import_new: false,
            policy: Policy::Skip,
        }
    }
}

pub struct CredentialsForm {
    pub vault_operation: VaultOperation,
    pub key_path: String,
    pub password: SecretString,
    pub confirmation: SecretString,
    pub use_key: bool,
    pub keep_key: bool,
}
impl Default for CredentialsForm {
    fn default() -> Self {
        Self {
            vault_operation: VaultOperation::Rekey,
            key_path: String::new(),
            password: SecretString::default(),
            confirmation: SecretString::default(),
            use_key: false,
            keep_key: true,
        }
    }
}

#[derive(Default)]
pub struct AuditForm {
    pub stale_days: String,
    pub breaches: bool,
    pub require_otp: bool,
}

#[derive(Default)]
pub struct SearchForm {
    pub query: String,
    pub name: String,
    pub username: String,
    pub url: String,
    pub notes: SecretString,
    pub weak: bool,
    pub descending: bool,
    pub kind: Option<ItemKind>,
    pub has_otp: Option<bool>,
    pub sort: SortField,
}

pub struct AuthenticatorForm {
    pub configuration: SecretString,
    pub activation: SecretString,
    pub code: SecretString,
    pub otp_copy_timeout: String,
    pub duo_interval: String,
    pub replace_duo: bool,
    pub mode: Mode,
}
impl Default for AuthenticatorForm {
    fn default() -> Self {
        Self {
            configuration: SecretString::default(),
            activation: SecretString::default(),
            code: SecretString::default(),
            otp_copy_timeout: String::new(),
            duo_interval: "5".into(),
            replace_duo: false,
            mode: Mode::Automatic,
        }
    }
}

pub struct BrowserForm {
    pub extension_id: String,
    pub browser: Browser,
}
impl Default for BrowserForm {
    fn default() -> Self {
        Self {
            extension_id: String::new(),
            browser: Browser::Chrome,
        }
    }
}

pub struct UtilitiesForm {
    pub operation_id: String,
    pub shell: clap_complete::Shell,
}
impl Default for UtilitiesForm {
    fn default() -> Self {
        Self {
            operation_id: String::new(),
            shell: clap_complete::Shell::Bash,
        }
    }
}

impl CredentialsForm {
    pub fn value(&self, confirm: bool) -> Result<PasswordType, String> {
        if self.use_key {
            Ok(PasswordType::Key(absolute(&self.key_path)?))
        } else {
            if self.password.is_empty() {
                return Err("Enter a password or choose a key file.".into());
            }
            if confirm && self.password != self.confirmation {
                return Err("The two passwords do not match.".into());
            }
            Ok(PasswordType::Password(self.password.clone().expose_owned()))
        }
    }
}

impl AuthenticatorForm {
    pub fn otp_timeout(&self, default: u8) -> Result<Option<u8>, String> {
        let timeout = if self.otp_copy_timeout.trim().is_empty() {
            default
        } else {
            self.otp_copy_timeout.trim().parse::<u8>().map_err(|_| {
                "OTP copy timeout must be a whole number from 0 to 255 seconds.".to_owned()
            })?
        };
        Ok((timeout > 0).then_some(timeout))
    }
    pub fn duo_interval_seconds(&self) -> Result<u64, String> {
        self.duo_interval
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|seconds| (3..=60).contains(seconds))
            .ok_or_else(|| {
                "Duo refresh interval must be a whole number from 3 to 60 seconds.".into()
            })
    }
}
