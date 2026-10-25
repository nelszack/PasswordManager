//! Desktop workflows use the same typed commands and receipts as the CLI.
#[cfg(test)]
mod tests;
mod view;

use super::*;
use password_manager::{
    cli::NativeBrowser,
    types::{
        AuditOptions, BackupRequest, ConflictPolicy, DuoCommand, DuoPushRequest, ImportRequest,
        OtpMode, TotpCommand,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    Recovery,
    Files,
    Security,
    Search,
    Browser,
}
impl Section {
    pub const ALL: [Self; 5] = [
        Self::Recovery,
        Self::Files,
        Self::Security,
        Self::Search,
        Self::Browser,
    ];
}
impl std::fmt::Display for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Recovery => "History, trash & audit",
            Self::Files => "Import, export & backups",
            Self::Security => "Vault security",
            Self::Search => "Advanced search",
            Self::Browser => "Browser integration",
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOperation {
    Backup,
    Restore,
    Import,
    Export,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultOperation {
    Rekey,
    Create,
    Delete,
}
impl std::fmt::Display for VaultOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rekey => "Change vault credentials",
            Self::Create => "Create vault",
            Self::Delete => "Delete selected vault",
        })
    }
}
impl std::fmt::Display for FileOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Backup => "Create encrypted backup",
            Self::Restore => "Restore encrypted backup",
            Self::Import => "Import items",
            Self::Export => "Export plaintext items",
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    Skip,
    Replace,
    KeepBoth,
}
impl From<Policy> for ConflictPolicy {
    fn from(value: Policy) -> Self {
        match value {
            Policy::Skip => Self::Skip,
            Policy::Replace => Self::Replace,
            Policy::KeepBoth => Self::KeepBoth,
        }
    }
}
impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Skip => "Skip duplicates",
            Self::Replace => "Replace duplicates",
            Self::KeepBoth => "Keep both",
        })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Browser {
    Chrome,
    Chromium,
    Helium,
}
impl std::fmt::Display for Browser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Automatic,
    Hotp,
    Totp,
}
impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Automatic => "Duo default",
            Self::Hotp => "HOTP (counter based)",
            Self::Totp => "TOTP (time based)",
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Choice {
    pub id: usize,
    pub label: String,
}
impl std::fmt::Display for Choice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}
/// A watch remains attached to the reviewed item even when the visible selection changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchTarget {
    pub choice: Choice,
    pub session: String,
    pub revision: u64,
}
impl WatchTarget {
    fn selected(app: &App) -> Result<Self, String> {
        let choice = app
            .workspace
            .selected
            .clone()
            .ok_or("Select an item first.")?;
        let item = app
            .items
            .iter()
            .find(|item| item.id == choice.id)
            .ok_or("Refresh the vault and select the item again.")?;
        Ok(Self {
            choice,
            session: app.session.clone().ok_or("Unlock a vault first.")?,
            revision: item.revision,
        })
    }
    fn same_context(&self, other: &Self) -> bool {
        self.choice.id == other.choice.id
            && self.session == other.session
            && self.revision == other.revision
    }
    pub fn current(&self, app: &App) -> bool {
        app.running
            && app.session.as_ref() == Some(&self.session)
            && app
                .items
                .iter()
                .any(|item| item.id == self.choice.id && item.revision == self.revision)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Path,
    KeyPath,
    Password,
    Confirmation,
    Configuration,
    Activation,
    Code,
    StaleDays,
    OtpCopyTimeout,
    DuoInterval,
    Query,
    Name,
    Username,
    Url,
    Notes,
    ExtensionId,
}
#[derive(Clone, Copy, Debug)]
pub enum Toggle {
    UseKey,
    Force,
    ImportNew,
    KeepKey,
    Breaches,
    RequireOtp,
    Weak,
    Descending,
    ReplaceDuo,
    WatchOtp,
    CopyWatchedOtp,
    OtpOptions,
    WatchDuo,
    NotifyDuo,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    History,
    RestorePassword(usize),
    Trash,
    RestoreTrash(usize),
    Purge(Option<usize>),
    Audit,
    Backup,
    RestoreBackup,
    PreviewImport,
    Import,
    Export,
    SetOtp,
    ShowOtp(bool),
    WatchOtp,
    CopyWatchedOtp,
    RemoveOtp,
    EnrollPasscodes,
    EnrollDuo,
    Requests,
    Respond(usize, bool),
    RemoveDuo,
    Rekey,
    NewVault,
    DeleteVault,
    Search,
    InstallHost,
    UpdateHost,
    Shortcut,
}
impl Action {
    pub fn edits_authenticator(self) -> bool {
        matches!(
            self,
            Self::SetOtp
                | Self::RemoveOtp
                | Self::EnrollPasscodes
                | Self::EnrollDuo
                | Self::RemoveDuo
        )
    }
    pub fn changes_vault(self) -> bool {
        matches!(
            self,
            Self::RestoreBackup | Self::Import | Self::NewVault | Self::DeleteVault | Self::Rekey
        )
    }
    pub fn local(self) -> bool {
        matches!(self, Self::InstallHost | Self::UpdateHost | Self::Shortcut)
    }
}
#[derive(Clone, Debug)]
pub enum Event {
    Section(Section),
    FileOperation(FileOperation),
    VaultOperation(VaultOperation),
    Field(Field, SecretString),
    Toggle(Toggle, bool),
    Select(Choice),
    Policy(Policy),
    Mode(Mode),
    Browser(Browser),
    Kind(Option<ItemKind>),
    Sort(SortField),
    HasOtp(Option<bool>),
    Run(Action),
    Confirm,
    Cancel,
    Pick(Field, bool),
    ClearResult,
    NotificationFinished(Result<(), String>),
}

pub struct Prepared {
    pub action: Action,
    pub command: ServerCommand,
    pub revision: Option<u64>,
    pub session: Option<String>,
    pub confirmation: Option<String>,
}
impl Drop for Prepared {
    fn drop(&mut self) {
        self.command.zeroize();
    }
}

pub struct State {
    pub section: Section,
    pub file_operation: FileOperation,
    pub vault_operation: VaultOperation,
    pub selected: Option<Choice>,
    pub path: String,
    pub key_path: String,
    pub password: SecretString,
    pub confirmation: SecretString,
    pub configuration: SecretString,
    pub activation: SecretString,
    pub code: SecretString,
    pub stale_days: String,
    pub otp_copy_timeout: String,
    pub duo_interval: String,
    pub query: String,
    pub name: String,
    pub username: String,
    pub url: String,
    pub notes: SecretString,
    pub extension_id: String,
    pub use_key: bool,
    pub force: bool,
    pub import_new: bool,
    pub keep_key: bool,
    pub breaches: bool,
    pub require_otp: bool,
    pub weak: bool,
    pub descending: bool,
    pub replace_duo: bool,
    pub watch_otp: bool,
    pub otp_options_open: bool,
    pub otp_inflight_target: Option<WatchTarget>,
    pub otp_result_target: Option<WatchTarget>,
    pub watch_duo: bool,
    pub copy_watched_otp: bool,
    pub notify_duo: bool,
    pub duo_watch_target: Option<WatchTarget>,
    pub duo_request_target: Option<WatchTarget>,
    pub duo_inflight_target: Option<WatchTarget>,
    pub otp_watch_target: Option<WatchTarget>,
    pub previous_otp: SecretString,
    duo_seen: std::collections::HashSet<String>,
    pub policy: Policy,
    pub mode: Mode,
    pub browser: Browser,
    pub kind: Option<ItemKind>,
    pub has_otp: Option<bool>,
    pub sort: SortField,
    pub duo_requests: Option<Vec<DuoPushRequest>>,
    history_inflight_target: Option<WatchTarget>,
    history_result_target: Option<WatchTarget>,
    pub result: Option<ResponsePayload>,
    pub result_until: Option<Instant>,
    pub prepared: Option<Prepared>,
    pub secret_epoch: u64,
    pub request_epoch: u64,
    pub last_watch: Instant,
}
impl Default for State {
    fn default() -> Self {
        Self {
            section: Section::Recovery,
            file_operation: FileOperation::Backup,
            vault_operation: VaultOperation::Rekey,
            selected: None,
            path: String::new(),
            key_path: String::new(),
            password: SecretString::default(),
            confirmation: SecretString::default(),
            configuration: SecretString::default(),
            activation: SecretString::default(),
            code: SecretString::default(),
            stale_days: String::new(),
            otp_copy_timeout: String::new(),
            duo_interval: "5".into(),
            query: String::new(),
            name: String::new(),
            username: String::new(),
            url: String::new(),
            notes: SecretString::default(),
            extension_id: String::new(),
            use_key: false,
            force: false,
            import_new: false,
            keep_key: true,
            breaches: false,
            require_otp: false,
            weak: false,
            descending: false,
            replace_duo: false,
            watch_otp: false,
            otp_options_open: false,
            otp_inflight_target: None,
            otp_result_target: None,
            watch_duo: false,
            copy_watched_otp: false,
            notify_duo: false,
            duo_watch_target: None,
            duo_request_target: None,
            duo_inflight_target: None,
            otp_watch_target: None,
            previous_otp: SecretString::default(),
            duo_seen: Default::default(),
            policy: Policy::Skip,
            mode: Mode::Automatic,
            browser: Browser::Chrome,
            kind: None,
            has_otp: None,
            sort: SortField::Name,
            duo_requests: None,
            history_inflight_target: None,
            history_result_target: None,
            result: None,
            result_until: None,
            prepared: None,
            secret_epoch: 0,
            request_epoch: 0,
            last_watch: Instant::now(),
        }
    }
}
impl State {
    pub fn clear_inputs(&mut self) {
        self.password.zeroize();
        self.confirmation.zeroize();
        self.configuration.zeroize();
        self.activation.zeroize();
        self.code.zeroize();
    }
    pub fn hide_secrets(&mut self) {
        self.secret_epoch += 1;
        self.otp_inflight_target = None;
        self.otp_result_target = None;
        self.watch_otp = false;
        self.otp_watch_target = None;
        self.previous_otp.zeroize();
        if self.result.as_ref().is_some_and(secret_result) {
            self.result = None;
        }
        self.result_until = None;
    }
    pub fn reset_duo(&mut self) {
        self.watch_duo = false;
        self.duo_watch_target = None;
        self.duo_inflight_target = None;
        self.duo_seen.clear();
        self.clear_duo_requests();
    }
    pub fn clear_duo_requests(&mut self) {
        self.duo_request_target = None;
        self.duo_requests = None;
        self.code.zeroize();
    }
    pub fn clear_vault(&mut self) {
        self.hide_secrets();
        self.reset_duo();
        self.clear_history();
        self.clear_inputs();
        self.notes.zeroize();
        self.selected = None;
        self.result = None;
        self.prepared = None;
    }
    pub fn edit(&mut self, field: Field, value: SecretString) {
        self.prepared = None;
        match field {
            Field::Password => self.password = value,
            Field::Confirmation => self.confirmation = value,
            Field::Configuration => self.configuration = value,
            Field::Activation => self.activation = value,
            Field::Code => self.code = value,
            Field::Notes => self.notes = value,
            field => {
                *match field {
                    Field::Path => &mut self.path,
                    Field::KeyPath => &mut self.key_path,
                    Field::StaleDays => &mut self.stale_days,
                    Field::OtpCopyTimeout => &mut self.otp_copy_timeout,
                    Field::DuoInterval => &mut self.duo_interval,
                    Field::Query => &mut self.query,
                    Field::Name => &mut self.name,
                    Field::Username => &mut self.username,
                    Field::Url => &mut self.url,
                    Field::ExtensionId => &mut self.extension_id,
                    _ => unreachable!(),
                } = value.expose_owned()
            }
        }
    }
    pub fn toggle(&mut self, toggle: Toggle, value: bool) {
        self.prepared = None;
        *match toggle {
            Toggle::UseKey => &mut self.use_key,
            Toggle::Force => &mut self.force,
            Toggle::ImportNew => &mut self.import_new,
            Toggle::KeepKey => &mut self.keep_key,
            Toggle::Breaches => &mut self.breaches,
            Toggle::RequireOtp => &mut self.require_otp,
            Toggle::Weak => &mut self.weak,
            Toggle::Descending => &mut self.descending,
            Toggle::ReplaceDuo => &mut self.replace_duo,
            Toggle::WatchOtp => &mut self.watch_otp,
            Toggle::OtpOptions => &mut self.otp_options_open,
            Toggle::WatchDuo => &mut self.watch_duo,
            Toggle::CopyWatchedOtp => &mut self.copy_watched_otp,
            Toggle::NotifyDuo => &mut self.notify_duo,
        } = value;
    }
    fn credentials(&self, confirm: bool) -> Result<PasswordType, String> {
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
    pub fn otp_result_for(
        &self,
        app: &App,
    ) -> Option<&password_manager::protocol::AuthenticatorResponse> {
        let target = self.otp_result_target.as_ref()?;
        if !app.running
            || app.session.as_ref() != Some(&target.session)
            || self
                .selected
                .as_ref()
                .is_none_or(|choice| choice.id != target.choice.id)
            || self
                .result_until
                .is_none_or(|deadline| Instant::now() >= deadline)
        {
            return None;
        }
        match &self.result {
            Some(ResponsePayload::Authenticator(code)) => Some(code),
            _ => None,
        }
    }
    pub fn duo_requests_for<'a>(&'a self, app: &App) -> Option<&'a [DuoPushRequest]> {
        let target = self.duo_request_target.as_ref()?;
        (target.current(app)
            && self
                .selected
                .as_ref()
                .is_some_and(|choice| choice.id == target.choice.id))
        .then_some(self.duo_requests.as_deref())
        .flatten()
    }
    fn clear_history(&mut self) {
        self.history_inflight_target = None;
        self.history_result_target = None;
        if matches!(&self.result, Some(ResponsePayload::History(_))) {
            self.result = None;
        }
    }
    fn history_for(&self, app: &App) -> Option<&password_manager::vault::HistoryPage> {
        let target = self.history_result_target.as_ref()?;
        if !target.current(app)
            || self
                .selected
                .as_ref()
                .is_none_or(|choice| choice.id != target.choice.id)
        {
            return None;
        }
        match &self.result {
            Some(ResponsePayload::History(page)) => Some(page),
            _ => None,
        }
    }
    /// Keep the reviewed snapshot stable, as interactive CLI watch does while
    /// awaiting a decision. Explicit fetches still bypass this automatic pause.
    pub fn duo_review_pending(&self, app: &App) -> bool {
        let Some(watch) = self.duo_watch_target.as_ref().filter(|_| self.watch_duo) else {
            return false;
        };
        if !self
            .duo_request_target
            .as_ref()
            .is_some_and(|target| target.same_context(watch) && target.current(app))
        {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.duo_requests
            .as_ref()
            .is_some_and(|requests| requests.iter().any(|request| request.expires_at > now))
    }
    pub fn prepare(&self, action: Action, app: &App) -> Result<Prepared, String> {
        self.prepare_for(action, app, None)
    }
    fn prepare_for(
        &self,
        action: Action,
        app: &App,
        watch: Option<&WatchTarget>,
    ) -> Result<Prepared, String> {
        if watch.is_some_and(|target| !target.current(app)) {
            return Err("The watched item changed. Select it and start watching again.".into());
        }
        if !app.running {
            return Err("Start the server first.".into());
        }
        let needs_item = matches!(
            action,
            Action::History
                | Action::RestorePassword(_)
                | Action::SetOtp
                | Action::ShowOtp(_)
                | Action::WatchOtp
                | Action::CopyWatchedOtp
                | Action::RemoveOtp
                | Action::EnrollPasscodes
                | Action::EnrollDuo
                | Action::Requests
                | Action::Respond(..)
                | Action::RemoveDuo
        );
        let editor_draft = app
            .draft
            .as_ref()
            .filter(|_| action.edits_authenticator() && app.tab == super::Tab::Vault);
        let editor_choice = match editor_draft {
            Some(draft) => Some(Choice {
                id: draft
                    .id
                    .ok_or("Save the new item before configuring authenticators.")?,
                label: String::new(),
            }),
            None => None,
        };
        let item = watch
            .map(|target| &target.choice)
            .or(editor_choice.as_ref())
            .or(self.selected.as_ref())
            .and_then(|choice| app.items.iter().find(|item| item.id == choice.id));
        if needs_item && item.is_none() {
            return Err("Select an item first. Refresh the vault if it changed.".into());
        }
        if let Some(draft) = editor_draft
            && draft.revision != item.map(|item| item.revision)
        {
            return Err(
                "This item changed. Refresh and reopen it before changing authenticators.".into(),
            );
        }
        let target = || Target::Id(item.expect("validated item selection").id);
        let mut confirmation = None;
        let mut revision = needs_item.then(|| item.unwrap().revision);
        let command = match action {
            Action::History => ServerCommand::History(target()),
            Action::RestorePassword(index) => {
                let Some(page) = self.history_for(app) else {
                    return Err(
                        "Reload password history for the selected item before restoring.".into(),
                    );
                };
                if index == 0 || index > page.history.len() {
                    return Err("Choose a saved password revision.".into());
                }
                confirmation = Some(format!(
                    "Replace the current password of {} with revision {index} from {}?",
                    item.unwrap().name,
                    page.history[index - 1]
                ));
                ServerCommand::RestorePassword {
                    target: target(),
                    revision: index,
                }
            }
            Action::Trash => ServerCommand::Trash,
            Action::RestoreTrash(id) | Action::Purge(Some(id)) => {
                let Some(ResponsePayload::Trash(page)) = &self.result else {
                    return Err("Load the trash first.".into());
                };
                let entry = page
                    .trash
                    .iter()
                    .find(|entry| entry.id == id)
                    .ok_or("The trash entry is no longer listed.")?;
                if matches!(action, Action::Purge(_)) {
                    confirmation = Some(format!(
                        "Permanently erase {} from trash? This cannot be undone.",
                        entry.name
                    ));
                    ServerCommand::PurgeTrash(Some(id))
                } else {
                    ServerCommand::RestoreTrash(id)
                }
            }
            Action::Purge(None) => {
                if !matches!(&self.result, Some(ResponsePayload::Trash(_))) {
                    return Err("Load the trash first.".into());
                }
                confirmation =
                    Some("Permanently erase every item in trash? This cannot be undone.".into());
                ServerCommand::PurgeTrash(None)
            }
            Action::Audit => ServerCommand::Audit(AuditOptions {
                stale_days: optional_number(&self.stale_days)?,
                check_breaches: self.breaches,
                require_totp: self.require_otp,
            }),
            Action::Backup | Action::RestoreBackup => {
                if action == Action::RestoreBackup && app.session.is_some() {
                    return Err("Lock the vault before restoring a backup.".into());
                }
                let request = BackupRequest {
                    path: absolute(&self.path)?,
                    key_pass: self.credentials(action == Action::Backup)?,
                    force: self.force,
                };
                confirmation = Some(if action == Action::Backup {
                    format!(
                        "Create an encrypted backup at {}{}?",
                        request.path,
                        if request.force {
                            ", replacing any existing file"
                        } else {
                            ""
                        }
                    )
                } else {
                    format!(
                        "Restore {} as a separate vault? Unlock it with its backup password or key.",
                        request.path
                    )
                });
                if action == Action::Backup {
                    ServerCommand::Backup(request)
                } else {
                    ServerCommand::RestoreBackup(request)
                }
            }
            Action::PreviewImport | Action::Import => {
                let preview = action == Action::PreviewImport;
                let request = ImportRequest {
                    path: absolute(&self.path)?,
                    new: self.import_new,
                    preview,
                    conflicts: self.policy.into(),
                    key_pass: if self.import_new && !preview {
                        Some(self.credentials(true)?)
                    } else {
                        None
                    },
                    password_history_limit: app.conf.recovery.password_history_limit,
                };
                if !preview {
                    confirmation = Some(format!(
                        "Import {} into {} using '{}'?",
                        request.path,
                        if request.new {
                            "a new vault"
                        } else {
                            "the unlocked vault"
                        },
                        self.policy
                    ));
                }
                ServerCommand::Import(request)
            }
            Action::Export => {
                let path = absolute(&self.path)?;
                confirmation = Some(format!(
                    "Export plaintext secrets to {path}{}? Anyone who can read this file can read its passwords. JSON preserves richer data than CSV.",
                    if self.force {
                        ", replacing any existing file"
                    } else {
                        ""
                    }
                ));
                ServerCommand::Export {
                    path,
                    force: self.force,
                }
            }
            Action::SetOtp => {
                if self.configuration.is_empty() {
                    return Err("Enter a Base32 secret or otpauth URI.".into());
                }
                confirmation = Some(format!(
                    "Set or replace the authenticator for {}?",
                    item.unwrap().name
                ));
                ServerCommand::Totp(TotpCommand::Set {
                    target: target(),
                    configuration: self.configuration.clone(),
                })
            }
            Action::ShowOtp(copy) => {
                ServerCommand::Totp(TotpCommand::Show {
                    target: target(),
                    copy_timeout: if copy {
                        Some(self.otp_timeout(app.conf.clipboard.timeout)?.ok_or(
                            "OTP copying is disabled because the current timeout is zero.",
                        )?)
                    } else {
                        None
                    },
                })
            }
            Action::WatchOtp => ServerCommand::Totp(TotpCommand::Watch {
                target: target(),
                copy_timeout: None,
            }),
            Action::CopyWatchedOtp => ServerCommand::Totp(TotpCommand::Watch {
                target: target(),
                copy_timeout: self
                    .otp_timeout(app.conf.clipboard.timeout)?
                    .ok_or("Enable OTP copying with a timeout greater than zero.")
                    .map(Some)?,
            }),
            Action::RemoveOtp => {
                confirmation = Some(format!(
                    "Remove the authenticator from {}?",
                    item.unwrap().name
                ));
                ServerCommand::Totp(TotpCommand::Remove { target: target() })
            }
            Action::EnrollPasscodes | Action::EnrollDuo => {
                if self.activation.is_empty() {
                    return Err("Enter a fresh Duo activation link.".into());
                }
                confirmation = Some(format!(
                    "Consume this Duo activation link and enroll {}{}?",
                    item.unwrap().name,
                    if action == Action::EnrollDuo && self.replace_duo {
                        ", replacing its enrollment"
                    } else {
                        ""
                    }
                ));
                let mode = match self.mode {
                    Mode::Automatic => None,
                    Mode::Hotp => Some(OtpMode::Hotp),
                    Mode::Totp => Some(OtpMode::Totp),
                };
                if action == Action::EnrollDuo {
                    ServerCommand::Duo(DuoCommand::Enroll {
                        target: target(),
                        activation: self.activation.clone(),
                        mode,
                        replace: self.replace_duo,
                    })
                } else {
                    ServerCommand::Totp(TotpCommand::Duo {
                        target: target(),
                        activation: self.activation.clone(),
                        mode: mode.unwrap_or(OtpMode::Hotp),
                    })
                }
            }
            Action::Requests => ServerCommand::Duo(DuoCommand::Requests { target: target() }),
            Action::Respond(index, approve) => {
                let Some(requests) = self.duo_requests_for(app) else {
                    return Err("Fetch and review pending Duo requests first.".into());
                };
                let request = requests
                    .get(index)
                    .ok_or("The selected request is no longer listed.")?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_secs();
                if now >= request.expires_at {
                    return Err("This request expired. Refresh pending requests.".into());
                }
                if approve {
                    if let Some(reason) = &request.unsupported {
                        return Err(format!("This request cannot be approved: {reason}"));
                    }
                    if let Some(digits) = request.code_digits
                        && (self.code.len() != digits
                            || !self.code.bytes().all(|b| b.is_ascii_digit()))
                    {
                        return Err(format!(
                            "Enter the {digits}-digit Verified Push code shown on the login page."
                        ));
                    }
                }
                confirmation = Some(format!(
                    "{} this Duo request?\nApplication: {}\nAccount: {}\nLocation: {}\n{}\nRequest: {}",
                    if approve { "Approve" } else { "Deny" },
                    request.application,
                    request.username,
                    request.location,
                    request.summary,
                    request.id
                ));
                ServerCommand::Duo(DuoCommand::Respond {
                    target: target(),
                    request_id: request.id.clone(),
                    fingerprint: request.fingerprint.clone(),
                    approve,
                    code: if approve {
                        self.code.clone()
                    } else {
                        SecretString::default()
                    },
                })
            }
            Action::RemoveDuo => {
                confirmation = Some(format!(
                    "Remove local Duo Push credentials for {}? Remove the device separately in Duo.",
                    item.unwrap().name
                ));
                ServerCommand::Duo(DuoCommand::Remove { target: target() })
            }
            Action::Rekey | Action::NewVault => {
                confirmation = Some(if action == Action::Rekey {
                    "Re-encrypt the unlocked vault with these new credentials? Keep a verified backup of the current vault and retain existing external keys.".into()
                } else {
                    "Create a new vault using these credentials? A new key path must be outside application data and must not already exist.".into()
                });
                let credentials = self.credentials(true)?;
                if action == Action::Rekey {
                    ServerCommand::Rekey(credentials)
                } else {
                    ServerCommand::New(credentials)
                }
            }
            Action::DeleteVault => {
                if app.session.is_some() {
                    return Err(
                        "Lock the vault, then select the vault to delete on the Vault tab.".into(),
                    );
                }
                let filename = app
                    .vault
                    .as_ref()
                    .ok_or("Select the vault to delete on the Vault tab.")?;
                confirmation = Some(format!(
                    "Permanently delete vault {filename}{}? All its entries and recovery data will be lost.",
                    if self.use_key && !self.keep_key {
                        " AND its external key file"
                    } else {
                        ""
                    }
                ));
                ServerCommand::Delete(Target::Vault {
                    key: self.credentials(false)?,
                    keep_key: self.keep_key,
                    vault_file: Some(filename.clone()),
                })
            }
            Action::Search => {
                revision = None;
                let nonempty = |value: &String| (!value.is_empty()).then(|| value.clone());
                ServerCommand::ManagementList(SearchFilter {
                    query: nonempty(&self.query),
                    name: nonempty(&self.name),
                    username: nonempty(&self.username),
                    url: nonempty(&self.url),
                    notes: (!self.notes.is_empty()).then(|| self.notes.clone()),
                    list: ListOptions {
                        kind: self.kind,
                        has_totp: self.has_otp,
                        weak: self.weak,
                        stale_days: optional_number(&self.stale_days)?,
                        sort: self.sort,
                        descending: self.descending,
                    },
                })
            }
            Action::InstallHost | Action::UpdateHost | Action::Shortcut => {
                return Err("This is a local desktop action.".into());
            }
        };
        if command.is_mutation() && app.pending.is_some() {
            return Err(
                "Review the previous uncertain operation before making another change.".into(),
            );
        }
        if command.is_mutation() && app.draft.as_ref().is_some_and(|draft| draft.dirty) {
            return Err(
                "Save or discard the unsaved item edits before changing authenticators or using Tools.".into(),
            );
        }
        Ok(Prepared {
            action,
            command,
            revision,
            session: app.session.clone(),
            confirmation,
        })
    }
    fn observe_otp(&mut self, code: &password_manager::protocol::AuthenticatorResponse) -> bool {
        let changed = self.previous_otp != code.code;
        self.previous_otp = code.code.clone();
        changed
    }
    fn observe_duo(&mut self, requests: &[DuoPushRequest]) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let pending: std::collections::HashSet<_> = requests
            .iter()
            .filter(|request| request.expires_at > now)
            .map(|request| request.fingerprint.clone())
            .collect();
        self.duo_seen
            .retain(|fingerprint| pending.contains(fingerprint));
        let mut fresh = false;
        for fingerprint in pending {
            fresh |= self.duo_seen.insert(fingerprint);
        }
        fresh
    }
    pub fn receive(&mut self, payload: ResponsePayload) {
        if let ResponsePayload::DuoRequests(requests) = payload {
            // Only the captured request context can bind a cache. Never infer it
            // from the current selection after the asynchronous read finishes.
            if let Some(target) = self.duo_inflight_target.take() {
                self.duo_request_target = Some(target);
                self.duo_requests = Some(requests);
            }
            return;
        }
        if secret_result(&payload) {
            if self.secret_epoch != self.request_epoch {
                return;
            }
            let seconds = match &payload {
                ResponsePayload::Authenticator(code) => code.expires_in.unwrap_or(15).min(15),
                _ => 15,
            };
            self.result_until = Some(Instant::now() + Duration::from_secs(seconds));
        } else {
            self.result_until = None;
        }
        self.otp_result_target = if matches!(payload, ResponsePayload::Authenticator(_)) {
            self.otp_inflight_target.take()
        } else {
            None
        };
        self.history_result_target = if matches!(&payload, ResponsePayload::History(_)) {
            // History belongs to the initiating request, even if the visible
            // selection changes before the reply is delivered.
            let Some(target) = self.history_inflight_target.take() else {
                return;
            };
            Some(target)
        } else {
            self.history_inflight_target = None;
            None
        };
        self.result = Some(payload);
    }
    pub fn duo_confirmation<'a>(&'a self, app: &'a App) -> Element<'a, super::Message> {
        view::confirmation(self, app).into()
    }
    pub fn account_authenticators<'a>(
        &'a self,
        app: &'a App,
        item: &'a password_manager::vault::ItemDetail,
    ) -> Element<'a, super::Message> {
        view::account_authenticators(self, app, item).into()
    }
    pub fn authenticator_editor<'a>(&'a self, app: &'a App) -> Element<'a, super::Message> {
        view::authenticator_editor(self, app).into()
    }
    pub fn view<'a>(&'a self, app: &'a App) -> Element<'a, super::Message> {
        view::view(self, app)
    }
}
fn secret_result(payload: &ResponsePayload) -> bool {
    matches!(
        payload,
        ResponsePayload::Secret(_) | ResponsePayload::Authenticator(_)
    )
}
pub fn absolute(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err("Choose a file path.".into());
    }
    std::path::absolute(value)
        .map_err(|e| e.to_string())?
        .into_os_string()
        .into_string()
        .map_err(|_| "File paths must contain valid Unicode.".into())
}
impl App {
    pub(super) fn stop_tool_watches(&mut self) {
        if self.polling {
            self.serial += 1;
            self.polling = false;
        }
        self.workspace.hide_secrets();
        self.workspace.reset_duo();
    }
    pub(super) fn fetch_selected_duo(&mut self) -> Task<super::Message> {
        // Opening an account is a one-shot read. Watching requires an explicit
        // toggle and remains bound to its own account across navigation.
        if self.tab != Tab::Vault
            || self.draft.is_some()
            || self.session.is_none()
            || !self.item.as_ref().is_some_and(|item| {
                item.has_duo
                    && self
                        .workspace
                        .selected
                        .as_ref()
                        .is_some_and(|choice| choice.id == item.id)
            })
        {
            return Task::none();
        }
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        if self
            .workspace
            .duo_requests_for(self)
            .is_some_and(|requests| requests.iter().any(|request| request.expires_at > now))
        {
            return Task::none();
        }
        self.workflow(Event::Run(Action::Requests))
    }
    /// Tick integration: call without a tab/section restriction after the normal
    /// status-check fairness gate. This method also pauses during confirmations.
    pub(super) fn poll_tool_watches(&mut self, now: Instant) -> Task<super::Message> {
        if self.busy
            || self.polling
            || self.workspace.prepared.is_some()
            || self.pending.is_some()
            || self.session.is_none()
            || !self.running
        {
            return Task::none();
        }
        let (action, target, seconds) = if self.workspace.watch_otp {
            (Action::WatchOtp, self.workspace.otp_watch_target.clone(), 1)
        } else if self.workspace.watch_duo {
            let seconds = match self.workspace.duo_interval_seconds() {
                Ok(seconds) => seconds,
                Err(error) => {
                    self.workspace.reset_duo();
                    self.notice = error;
                    return Task::none();
                }
            };
            (
                Action::Requests,
                self.workspace.duo_watch_target.clone(),
                seconds,
            )
        } else {
            return Task::none();
        };
        let Some(target) = target else {
            return Task::none();
        };
        if !target.current(self)
            || action == Action::Requests
                && !self
                    .items
                    .iter()
                    .any(|item| item.id == target.choice.id && item.has_duo)
        {
            self.stop_tool_watches();
            self.notice = "The watched item changed. Select it and start watching again.".into();
            return Task::none();
        }
        if action == Action::Requests && self.workspace.duo_review_pending(self) {
            return Task::none();
        }
        if now.saturating_duration_since(self.workspace.last_watch) < Duration::from_secs(seconds) {
            return Task::none();
        }
        match self.workspace.prepare_for(action, self, Some(&target)) {
            Ok(prepared) => self.execute_workflow(prepared),
            Err(error) => {
                self.stop_tool_watches();
                self.notice = error;
                Task::none()
            }
        }
    }
    /// Complete both WatchOtp and CopyWatchedOtp here. Every tick starts with a
    /// passive fetch; only a newly observed code schedules the copy fetch.
    pub(super) fn complete_otp_watch(
        &mut self,
        action: Action,
        payload: ResponsePayload,
    ) -> Task<super::Message> {
        let Some(target) = self.workspace.otp_watch_target.clone() else {
            return Task::none();
        };
        if !self.workspace.watch_otp
            || !target.current(self)
            || self.workspace.request_epoch != self.workspace.secret_epoch
        {
            return Task::none();
        }
        let ResponsePayload::Authenticator(code) = &payload else {
            self.workspace.hide_secrets();
            self.notice = "Invalid TOTP watch response.".into();
            return Task::none();
        };
        if !code.valid() || code.mode != "totp" || code.expires_in == Some(0) {
            self.workspace.hide_secrets();
            self.notice = "Invalid TOTP watch response.".into();
            return Task::none();
        }
        let first_result = self.workspace.result.is_none();
        let reveal = first_result
            && self.tab == Tab::Tools
            && self.workspace.section == Section::Security
            && self
                .workspace
                .selected
                .as_ref()
                .is_some_and(|choice| choice.id == target.choice.id);
        let changed = self.workspace.observe_otp(code);
        self.workspace.receive(payload);
        if action == Action::WatchOtp
            && changed
            && self.workspace.copy_watched_otp
            && self.workspace.prepared.is_none()
            && self.pending.is_none()
        {
            return Task::batch([
                self.launch(Job::WatchCopyDefaults, backend::reload_settings),
                if reveal { show_result() } else { Task::none() },
            ]);
        }
        if reveal { show_result() } else { Task::none() }
    }
    /// A fresh configuration snapshot arrives before every automatic copy.
    /// Focus loss, a lock, navigation, or an item edit can invalidate the watch
    /// while that read is pending; never send a copy for that old context.
    pub(super) fn copy_watched_otp(&mut self) -> Task<super::Message> {
        let Some(target) = self.workspace.otp_watch_target.clone() else {
            return Task::none();
        };
        if !self.workspace.watch_otp
            || !self.workspace.copy_watched_otp
            || !target.current(self)
            || self.workspace.request_epoch != self.workspace.secret_epoch
            || self.workspace.prepared.is_some()
            || self.pending.is_some()
        {
            return Task::none();
        }
        if matches!(
            self.workspace.otp_timeout(self.conf.clipboard.timeout),
            Ok(None)
        ) {
            self.workspace.copy_watched_otp = false;
            self.notice =
                "Copying watched codes stopped because the current timeout is zero.".into();
            return Task::none();
        }
        match self
            .workspace
            .prepare_for(Action::CopyWatchedOtp, self, Some(&target))
        {
            Ok(prepared) => self.execute_workflow(prepared),
            Err(error) => {
                self.workspace.hide_secrets();
                self.notice = error;
                Task::none()
            }
        }
    }
    /// Complete Requests here to validate the captured cache context and emit
    /// optional generic, passive desktop alerts for newly seen fingerprints.
    pub(super) fn complete_duo_requests(
        &mut self,
        payload: ResponsePayload,
    ) -> Task<super::Message> {
        let Some(target) = self.workspace.duo_inflight_target.as_ref() else {
            return Task::none();
        };
        if !target.current(self) {
            self.workspace.duo_inflight_target = None;
            return Task::none();
        }
        let watching = self.workspace.watch_duo
            && self
                .workspace
                .duo_watch_target
                .as_ref()
                .is_some_and(|watch| watch.same_context(target));
        let notify = if let ResponsePayload::DuoRequests(requests) = &payload {
            watching && self.workspace.observe_duo(requests) && self.workspace.notify_duo
        } else {
            false
        };
        self.workspace.receive(payload);
        if notify {
            return Task::perform(
                async {
                    tokio::task::spawn_blocking(notify_duo)
                        .await
                        .unwrap_or_else(|_| Err("Desktop notification could not be delivered. Review Duo requests on the account.".into()))
                },
                |ok| super::Message::Workflow(Event::NotificationFinished(ok)),
            );
        }
        Task::none()
    }
    pub(super) fn workflow(&mut self, event: Event) -> Task<super::Message> {
        // Cancel obsolete passive reads when their selection or screen changes.
        // They never consume HOTP counters or send Duo decisions.
        if self.polling
            && matches!(
                &event,
                Event::Section(_)
                    | Event::FileOperation(_)
                    | Event::VaultOperation(_)
                    | Event::Select(_)
                    | Event::Run(_)
                    | Event::ClearResult
                    | Event::Toggle(_, _)
            )
        {
            self.serial += 1;
            self.polling = false;
        }
        match event {
            Event::Section(section) => {
                self.workspace.hide_secrets();
                self.workspace.clear_history();
                self.workspace.section = section;
                self.workspace.result = None;
                self.workspace.prepared = None;
                return show_form();
            }
            Event::FileOperation(operation) => {
                self.workspace.file_operation = operation;
                self.workspace.prepared = None;
                self.workspace.result = None;
                self.workspace.clear_inputs();
                return show_form();
            }
            Event::VaultOperation(operation) => {
                self.workspace.vault_operation = operation;
                self.workspace.prepared = None;
                self.workspace.clear_inputs();
            }
            Event::Field(field, value) => self.workspace.edit(field, value),
            Event::Toggle(toggle, value) => {
                self.workspace.toggle(toggle, value);
                if matches!(toggle, Toggle::WatchOtp | Toggle::WatchDuo) && value {
                    let target = match WatchTarget::selected(self) {
                        Ok(target) => target,
                        Err(error) => {
                            self.stop_tool_watches();
                            self.notice = error;
                            return Task::none();
                        }
                    };
                    let action = if matches!(toggle, Toggle::WatchOtp) {
                        let timeout = self.workspace.otp_timeout(self.conf.clipboard.timeout);
                        if let Err(error) = timeout.as_ref() {
                            self.workspace.hide_secrets();
                            self.notice = error.clone();
                            return Task::none();
                        }
                        if self.workspace.copy_watched_otp && timeout.unwrap().is_none() {
                            self.workspace.hide_secrets();
                            self.notice =
                                "Set an OTP copy timeout greater than zero to watch and copy."
                                    .into();
                            return Task::none();
                        }
                        self.workspace.reset_duo();
                        self.workspace.otp_watch_target = Some(target.clone());
                        self.workspace.previous_otp.zeroize();
                        Action::WatchOtp
                    } else {
                        if let Err(error) = self.workspace.duo_interval_seconds() {
                            self.workspace.reset_duo();
                            self.notice = error;
                            return Task::none();
                        }
                        if !self
                            .items
                            .iter()
                            .any(|item| item.id == target.choice.id && item.has_duo)
                        {
                            self.workspace.reset_duo();
                            self.notice = "Select a Push-enrolled item to watch requests.".into();
                            return Task::none();
                        }
                        self.workspace.hide_secrets();
                        self.workspace.clear_duo_requests();
                        self.workspace.duo_seen.clear();
                        self.workspace.duo_watch_target = Some(target.clone());
                        Action::Requests
                    };
                    return match self.workspace.prepare_for(action, self, Some(&target)) {
                        Ok(prepared) => self.execute_workflow(prepared),
                        Err(error) => {
                            self.stop_tool_watches();
                            self.notice = error;
                            Task::none()
                        }
                    };
                }
                if matches!(toggle, Toggle::WatchDuo) && !value {
                    self.workspace.reset_duo();
                }
                if matches!(toggle, Toggle::WatchOtp) && !value {
                    self.workspace.hide_secrets();
                }
            }
            Event::Select(choice) => {
                self.workspace.hide_secrets();
                self.workspace.clear_duo_requests();
                self.workspace.clear_history();
                self.workspace.selected = Some(choice);
                self.workspace.result = None;
                self.workspace.prepared = None;
                return show_form();
            }
            Event::Policy(policy) => {
                self.workspace.policy = policy;
                self.workspace.prepared = None;
            }
            Event::Mode(mode) => {
                self.workspace.mode = mode;
                self.workspace.prepared = None;
            }
            Event::Browser(browser) => self.workspace.browser = browser,
            Event::Kind(kind) => self.workspace.kind = kind,
            Event::Sort(sort) => self.workspace.sort = sort,
            Event::HasOtp(has_otp) => self.workspace.has_otp = has_otp,
            Event::Pick(field, save) => {
                self.workspace.prepared = None;
                self.serial += 1;
                self.busy = true;
                self.polling = false;
                return file_picker::pick_workflow_file(self.serial, field, save);
            }
            Event::ClearResult => {
                self.workspace.clear_history();
                self.workspace.result = None;
                self.workspace.prepared = None;
            }
            Event::NotificationFinished(result) => {
                if let Err(reason) = result {
                    self.notice = reason;
                }
            }
            Event::Cancel => self.workspace.prepared = None,
            Event::Confirm => {
                if let Some(prepared) = self.workspace.prepared.take() {
                    return self.execute_workflow(prepared);
                }
            }
            Event::Run(action) if action.local() => {
                let extension_id = self.workspace.extension_id.clone();
                let browser = match self.workspace.browser {
                    Browser::Chrome => NativeBrowser::Chrome,
                    Browser::Chromium => NativeBrowser::Chromium,
                    Browser::Helium => NativeBrowser::Helium,
                };
                return self.launch(Job::Local, move || {
                    let path = match action {
                        Action::InstallHost => {
                            password_manager::native_messaging::install(&extension_id, browser)
                        }
                        Action::UpdateHost => password_manager::native_messaging::update(),
                        Action::Shortcut => crate::desktop::install_shortcut(),
                        _ => unreachable!(),
                    }
                    .map_err(Failure::from)?;
                    Ok(Reply::Local(format!(
                        "Installed at {}. Reload the extension after browser bridge changes.",
                        path.display()
                    )))
                });
            }
            Event::Run(action) => match self.workspace.prepare(action, self) {
                Ok(prepared) if prepared.confirmation.is_some() => {
                    self.workspace.prepared = Some(prepared);
                    return if action.edits_authenticator() && self.tab == super::Tab::Vault {
                        iced::widget::operation::snap_to_end("credential-editor")
                    } else if matches!(action, Action::Respond(..)) && self.tab == Tab::Vault {
                        iced::widget::operation::snap_to(
                            "account-details",
                            iced::widget::operation::RelativeOffset::START,
                        )
                    } else if matches!(action, Action::Respond(..)) {
                        show_form()
                    } else {
                        show_result()
                    };
                }
                Ok(prepared) => return self.execute_workflow(prepared),
                Err(error) => {
                    self.notice = error;
                    if matches!(action, Action::WatchOtp | Action::CopyWatchedOtp) {
                        self.workspace.hide_secrets();
                    }
                }
            },
        }
        Task::none()
    }
    fn execute_workflow(&mut self, mut prepared: Prepared) -> Task<super::Message> {
        if prepared.session != self.session {
            self.notice = "The vault session changed. Review this operation again.".into();
            return Task::none();
        }
        if prepared.command.is_mutation() && self.pending.is_some() {
            self.notice =
                "Review the previous uncertain operation before making another change.".into();
            return Task::none();
        }
        if prepared.command.is_mutation() && self.draft.as_ref().is_some_and(|draft| draft.dirty) {
            self.notice =
                "Save or discard the unsaved item edits before changing authenticators or using Tools.".into();
            return Task::none();
        }
        if matches!(
            prepared.action,
            Action::SetOtp
                | Action::EnrollPasscodes
                | Action::EnrollDuo
                | Action::Respond(..)
                | Action::Backup
                | Action::RestoreBackup
                | Action::Import
                | Action::Rekey
                | Action::NewVault
                | Action::DeleteVault
        ) {
            self.workspace.clear_inputs();
        }
        let context = match (
            prepared.command.revision_target(),
            prepared.revision,
            prepared.session.as_ref(),
        ) {
            (Some(Target::Id(id)), Some(revision), Some(session)) => self
                .items
                .iter()
                .find(|item| item.id == *id)
                .map(|item| WatchTarget {
                    choice: Choice {
                        id: *id,
                        label: format!("{} · {}", id, item.name),
                    },
                    revision,
                    session: session.clone(),
                }),
            _ => None,
        };
        if matches!(prepared.action, Action::RestorePassword(_))
            && (self.workspace.history_for(self).is_none()
                || !context.as_ref().is_some_and(|target| {
                    self.workspace
                        .history_result_target
                        .as_ref()
                        .is_some_and(|history| history.same_context(target))
                }))
        {
            self.notice = "Reload password history for the selected item before restoring.".into();
            return Task::none();
        }
        if prepared.action == Action::History {
            // A failed replacement request must not relabel an older page.
            self.workspace.clear_history();
            self.workspace.history_inflight_target = context.clone();
        }
        if matches!(
            prepared.action,
            Action::ShowOtp(_) | Action::WatchOtp | Action::CopyWatchedOtp
        ) {
            self.workspace.otp_inflight_target = context.clone();
        }
        if prepared.action == Action::Requests {
            self.workspace.duo_inflight_target = context;
        }
        self.workspace.request_epoch = self.workspace.secret_epoch;
        self.workspace.last_watch = Instant::now();
        let command = std::mem::replace(&mut prepared.command, ServerCommand::Status);
        let passive = matches!(prepared.action, Action::WatchOtp | Action::Requests);
        let task = self.request(Job::Workflow(prepared.action), command, prepared.revision);
        if passive {
            self.busy = false;
            self.polling = true;
        }
        task
    }
}
pub fn show_result() -> Task<super::Message> {
    iced::widget::operation::snap_to_end("vault-tools")
}
pub fn show_form() -> Task<super::Message> {
    iced::widget::operation::snap_to(
        "vault-tools",
        iced::widget::operation::RelativeOffset::START,
    )
}
fn optional_number(value: &str) -> Result<Option<u64>, String> {
    if value.trim().is_empty() {
        Ok(None)
    } else {
        value
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| "Days must be a nonnegative whole number.".into())
    }
}

/// Passive notification: no request metadata, codes, or approval action is sent
/// to the desktop notification service.
fn notify_duo() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut command = std::process::Command::new("notify-send");
        command.args([
            "--app-name=Password Manager",
            "--",
            "Duo login request",
            "Open Password Manager to review pending requests.",
        ]);
        command
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = std::process::Command::new("osascript");
        command.args(["-e", r#"display notification "Open Password Manager to review pending requests." with title "Duo login request""#]);
        command
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        use std::os::windows::process::CommandExt;
        let mut command = std::process::Command::new("powershell.exe");
        // Fixed script only; no vault or request data enters PowerShell/XML.
        command.creation_flags(0x08000000).args([
            "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
            r#"$ErrorActionPreference = 'Stop'; try {
    # Get-StartApps returns installed Start-menu AUMIDs. Never invent one for
    # this unpackaged executable or create/modify a user's shortcut/registry.
    $sender = Get-StartApps | Where-Object { $_.AppID -eq 'Microsoft.Windows.PowerShell' -or $_.Name -eq 'Windows PowerShell' -or $_.AppID -like '*WindowsPowerShell*v1.0*powershell.exe' } | Select-Object -First 1;
    if ($null -eq $sender) { exit 2 };
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null;
    [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null;
    $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($sender.AppID);
    if ($notifier.Setting.ToString() -ne 'Enabled') { exit 4 };
    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument;
    $xml.LoadXml('<toast><visual><binding template="ToastGeneric"><text>Password Manager: Duo login request</text><text>Open Password Manager to review pending requests. Sent via Windows PowerShell.</text></binding></visual></toast>');
    $toast = [Windows.UI.Notifications.ToastNotification]::new($xml);
    $notifier.Show($toast);
} catch { exit 3 }"#,
        ]);
        command
    };
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    {
        let status = command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map_err(|_| {
                "Desktop notification command is unavailable. Review Duo requests on the account."
                    .to_owned()
            })?;
        if status.success() {
            return Ok(());
        }
        #[cfg(target_os = "windows")]
        {
            Err(match status.code() {
                Some(2) => "Windows notifications need a registered Windows PowerShell Start-menu sender, which is unavailable. Review Duo requests on the account.",
                Some(4) => "Windows notifications are disabled for the Windows PowerShell sender. Review Duo requests on the account.",
                _ => "Windows could not send an alert through its registered Windows PowerShell sender. Review Duo requests on the account.",
            }.into())
        }
        #[cfg(not(target_os = "windows"))]
        Err(
            "Desktop notification could not be delivered. Review Duo requests on the account."
                .into(),
        )
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(
            "Desktop notifications are unavailable on this platform. Review Duo requests on the account."
                .into(),
        )
    }
}
