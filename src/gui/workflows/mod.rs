//! Desktop workflows use the same typed commands and receipts as the CLI.
mod completion;
mod forms;
#[cfg(test)]
mod tests;
mod view;
use forms::*;

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
    Overview,
    Audit,
    Trash,
    Recovery,
    Files,
    Security,
    Search,
    Browser,
    Utilities,
}
impl std::fmt::Display for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Overview => "All tools",
            Self::Audit => "Vault health",
            Self::Trash => "Deleted items",
            Self::Recovery => "Password history",
            Self::Files => "Import, export & backups",
            Self::Security => "Vault security",
            Self::Search => "Advanced search",
            Self::Browser => "Browser integration",
            Self::Utilities => "CLI utilities",
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
            session: app
                .connection
                .session
                .clone()
                .ok_or("Unlock a vault first.")?,
            revision: item.revision,
        })
    }
    fn same_context(&self, other: &Self) -> bool {
        self.choice.id == other.choice.id
            && self.session == other.session
            && self.revision == other.revision
    }
    pub fn current(&self, app: &App) -> bool {
        app.connection.running
            && app.connection.session.as_ref() == Some(&self.session)
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
    OperationId,
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
    OperationStatus,
    Completions,
}
impl Action {
    pub fn confirm_label(self) -> &'static str {
        match self {
            Self::Backup => "Create encrypted backup",
            Self::RestoreBackup => "Restore as a new vault",
            Self::Import => "Import items",
            Self::Export => "Export plaintext secrets",
            Self::NewVault => "Create vault",
            Self::Rekey => "Change vault credentials",
            Self::DeleteVault => "Permanently delete vault",
            Self::Purge(_) => "Permanently erase",
            Self::RestorePassword(_) => "Restore this password",
            Self::RemoveOtp => "Remove authenticator",
            Self::RemoveDuo => "Remove Duo enrollment",
            Self::Respond(_, true) => "Approve login",
            Self::Respond(_, false) => "Deny login",
            _ => "Apply this change",
        }
    }
    pub fn dangerous(self, overwrite: bool) -> bool {
        matches!(
            self,
            Self::DeleteVault
                | Self::Purge(_)
                | Self::Export
                | Self::Rekey
                | Self::RemoveOtp
                | Self::RemoveDuo
                | Self::RestorePassword(_)
        ) || (overwrite && matches!(self, Self::Backup))
    }
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
        matches!(
            self,
            Self::InstallHost | Self::UpdateHost | Self::Shortcut | Self::Completions
        )
    }
}
#[derive(Clone, Debug)]
pub enum Event {
    Section(Section),
    ShowResults(bool),
    FileOperation(FileOperation),
    VaultOperation(VaultOperation),
    Field(Field, SecretString),
    Toggle(Toggle, bool),
    Select(Choice),
    Policy(Policy),
    Mode(Mode),
    Browser(Browser),
    Shell(clap_complete::Shell),
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

/// Enablement and polling are independent: a one-shot read need not start a watch.
#[derive(Default)]
pub struct OtpState {
    pub watch: Option<WatchTarget>,
    pub inflight: Option<WatchTarget>,
    pub result_target: Option<WatchTarget>,
    pub previous: SecretString,
    pub copy: bool,
    pub options_open: bool,
}
#[derive(Default)]
pub struct DuoState {
    pub watch: Option<WatchTarget>,
    pub inflight: Option<WatchTarget>,
    pub result: Option<DuoRequests>,
    seen: std::collections::HashSet<String>,
    pub notify: bool,
}
pub struct DuoRequests {
    pub target: WatchTarget,
    pub requests: Vec<DuoPushRequest>,
}
#[derive(Default)]
pub struct HistoryState {
    inflight: Option<WatchTarget>,
    result_target: Option<WatchTarget>,
}

pub struct State {
    pub files: FilesForm,
    pub credentials: CredentialsForm,
    pub audit: AuditForm,
    pub search: SearchForm,
    pub authenticator: AuthenticatorForm,
    pub browser: BrowserForm,
    pub utilities: UtilitiesForm,

    pub otp: OtpState,
    pub duo: DuoState,
    pub history: HistoryState,
    pub section: Section,
    pub show_results: bool,
    pub selected: Option<Choice>,
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
            files: FilesForm::default(),
            credentials: CredentialsForm::default(),
            audit: AuditForm::default(),
            search: SearchForm::default(),
            authenticator: AuthenticatorForm::default(),
            browser: BrowserForm::default(),
            utilities: UtilitiesForm::default(),

            otp: OtpState::default(),
            duo: DuoState::default(),
            history: HistoryState::default(),
            section: Section::Overview,
            show_results: false,
            selected: None,
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
        self.credentials.password.zeroize();
        self.credentials.confirmation.zeroize();
        self.authenticator.configuration.zeroize();
        self.authenticator.activation.zeroize();
        self.authenticator.code.zeroize();
    }
    pub fn hide_secrets(&mut self) {
        self.secret_epoch += 1;
        self.otp.inflight = None;
        self.otp.result_target = None;
        self.otp.watch = None;
        self.otp.previous.zeroize();
        if self.result.as_ref().is_some_and(secret_result) {
            self.result = None;
        }
        self.result_until = None;
    }
    pub fn reset_duo(&mut self) {
        self.duo.watch = None;
        self.duo.inflight = None;
        self.duo.seen.clear();
        self.clear_duo_requests();
    }
    pub fn clear_duo_requests(&mut self) {
        self.duo.result = None;
        self.authenticator.code.zeroize();
    }
    pub fn clear_vault(&mut self) {
        self.hide_secrets();
        self.reset_duo();
        self.clear_history();
        self.clear_inputs();
        self.search.notes.zeroize();
        self.selected = None;
        self.result = None;
        self.prepared = None;
    }
    pub fn edit(&mut self, field: Field, value: SecretString) {
        self.prepared = None;
        match field {
            Field::Password => self.credentials.password = value,
            Field::Confirmation => self.credentials.confirmation = value,
            Field::Configuration => self.authenticator.configuration = value,
            Field::Activation => self.authenticator.activation = value,
            Field::Code => self.authenticator.code = value,
            Field::Notes => self.search.notes = value,
            field => {
                *match field {
                    Field::Path => &mut self.files.path,
                    Field::KeyPath => &mut self.credentials.key_path,
                    Field::StaleDays => &mut self.audit.stale_days,
                    Field::OtpCopyTimeout => &mut self.authenticator.otp_copy_timeout,
                    Field::DuoInterval => &mut self.authenticator.duo_interval,
                    Field::Query => &mut self.search.query,
                    Field::Name => &mut self.search.name,
                    Field::Username => &mut self.search.username,
                    Field::Url => &mut self.search.url,
                    Field::ExtensionId => &mut self.browser.extension_id,
                    Field::OperationId => &mut self.utilities.operation_id,
                    _ => unreachable!(),
                } = value.expose_owned()
            }
        }
    }
    pub fn toggle(&mut self, toggle: Toggle, value: bool) {
        self.prepared = None;
        *match toggle {
            Toggle::UseKey => &mut self.credentials.use_key,
            Toggle::Force => &mut self.files.force,
            Toggle::ImportNew => &mut self.files.import_new,
            Toggle::KeepKey => &mut self.credentials.keep_key,
            Toggle::Breaches => &mut self.audit.breaches,
            Toggle::RequireOtp => &mut self.audit.require_otp,
            Toggle::Weak => &mut self.search.weak,
            Toggle::Descending => &mut self.search.descending,
            Toggle::ReplaceDuo => &mut self.authenticator.replace_duo,
            Toggle::WatchOtp | Toggle::WatchDuo => return,
            Toggle::OtpOptions => &mut self.otp.options_open,
            Toggle::CopyWatchedOtp => &mut self.otp.copy,
            Toggle::NotifyDuo => &mut self.duo.notify,
        } = value;
    }
    pub fn otp_result_for(
        &self,
        app: &App,
    ) -> Option<&password_manager::protocol::AuthenticatorResponse> {
        let target = self.otp.result_target.as_ref()?;
        if !app.connection.running
            || app.connection.session.as_ref() != Some(&target.session)
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
        let result = self.duo.result.as_ref()?;
        let target = &result.target;
        (target.current(app)
            && self
                .selected
                .as_ref()
                .is_some_and(|choice| choice.id == target.choice.id))
        .then_some(result.requests.as_slice())
    }
    fn clear_history(&mut self) {
        self.history.inflight = None;
        self.history.result_target = None;
        if matches!(&self.result, Some(ResponsePayload::History(_))) {
            self.result = None;
        }
    }
    fn history_for(&self, app: &App) -> Option<&password_manager::vault::HistoryPage> {
        let target = self.history.result_target.as_ref()?;
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
        let Some(watch) = self.duo.watch.as_ref() else {
            return false;
        };
        let Some(result) = &self.duo.result else {
            return false;
        };
        if !result.target.same_context(watch) || !result.target.current(app) {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        result
            .requests
            .iter()
            .any(|request| request.expires_at > now)
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
        if !app.connection.running {
            return Err("Start the server first.".into());
        }
        // A queued action can outlive the unlocked UI that offered it. Never
        // dispatch a current-vault operation without an expected session: a
        // different client could unlock another vault before it reaches us.
        let needs_session = match action {
            Action::NewVault
            | Action::RestoreBackup
            | Action::DeleteVault
            | Action::OperationStatus => false,
            Action::Import | Action::PreviewImport => !self.files.import_new,
            _ => true,
        };
        if needs_session && app.connection.session.is_none() {
            return Err("Unlock a vault first.".into());
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
            .editor
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
            Action::OperationStatus => {
                let id = self.utilities.operation_id.trim();
                if id.is_empty()
                    || id.len() > 128
                    || !id
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
                {
                    return Err(
                        "Operation ID must contain 1–128 letters, digits, hyphens or underscores."
                            .into(),
                    );
                }
                ServerCommand::OperationStatus(id.to_owned())
            }
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
                stale_days: optional_number(&self.audit.stale_days)?,
                check_breaches: self.audit.breaches,
                require_totp: self.audit.require_otp,
            }),
            Action::Backup | Action::RestoreBackup => {
                if action == Action::RestoreBackup && app.connection.session.is_some() {
                    return Err("Lock the vault before restoring a backup.".into());
                }
                let request = BackupRequest {
                    path: absolute(&self.files.path)?,
                    key_pass: self.credentials.value(action == Action::Backup)?,
                    force: self.files.force,
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
                    path: absolute(&self.files.path)?,
                    new: self.files.import_new,
                    preview,
                    conflicts: self.files.policy.into(),
                    key_pass: if self.files.import_new && !preview {
                        Some(self.credentials.value(true)?)
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
                        self.files.policy
                    ));
                }
                ServerCommand::Import(request)
            }
            Action::Export => {
                let path = absolute(&self.files.path)?;
                confirmation = Some(format!(
                    "Export plaintext secrets to {path}{}? Anyone who can read this file can read its passwords. JSON preserves richer data than CSV.",
                    if self.files.force {
                        ", replacing any existing file"
                    } else {
                        ""
                    }
                ));
                ServerCommand::Export {
                    path,
                    force: self.files.force,
                }
            }
            Action::SetOtp => {
                if self.authenticator.configuration.is_empty() {
                    return Err("Enter a Base32 secret or otpauth URI.".into());
                }
                confirmation = Some(format!(
                    "Set or replace the authenticator for {}?",
                    item.unwrap().name
                ));
                ServerCommand::Totp(TotpCommand::Set {
                    target: target(),
                    configuration: self.authenticator.configuration.clone(),
                })
            }
            Action::ShowOtp(copy) => ServerCommand::Totp(TotpCommand::Show {
                target: target(),
                copy_timeout: if copy {
                    Some(
                        self.authenticator
                            .otp_timeout(app.conf.clipboard.timeout)?
                            .ok_or(
                                "OTP copying is disabled because the current timeout is zero.",
                            )?,
                    )
                } else {
                    None
                },
            }),
            Action::WatchOtp => ServerCommand::Totp(TotpCommand::Watch {
                target: target(),
                copy_timeout: None,
            }),
            Action::CopyWatchedOtp => ServerCommand::Totp(TotpCommand::Watch {
                target: target(),
                copy_timeout: self
                    .authenticator
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
                if self.authenticator.activation.is_empty() {
                    return Err("Enter a fresh Duo activation link.".into());
                }
                confirmation = Some(format!(
                    "Consume this Duo activation link and enroll {}{}?",
                    item.unwrap().name,
                    if action == Action::EnrollDuo && self.authenticator.replace_duo {
                        ", replacing its enrollment"
                    } else {
                        ""
                    }
                ));
                let mode = match self.authenticator.mode {
                    Mode::Automatic => None,
                    Mode::Hotp => Some(OtpMode::Hotp),
                    Mode::Totp => Some(OtpMode::Totp),
                };
                if action == Action::EnrollDuo {
                    ServerCommand::Duo(DuoCommand::Enroll {
                        target: target(),
                        activation: self.authenticator.activation.clone(),
                        mode,
                        replace: self.authenticator.replace_duo,
                    })
                } else {
                    ServerCommand::Totp(TotpCommand::Duo {
                        target: target(),
                        activation: self.authenticator.activation.clone(),
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
                        && (self.authenticator.code.len() != digits
                            || !self.authenticator.code.bytes().all(|b| b.is_ascii_digit()))
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
                        self.authenticator.code.clone()
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
                let credentials = self.credentials.value(true)?;
                if action == Action::Rekey {
                    ServerCommand::Rekey(credentials)
                } else {
                    ServerCommand::New(credentials)
                }
            }
            Action::DeleteVault => {
                if app.connection.session.is_some() {
                    return Err(
                        "Lock the vault, then select the vault to delete on the Vault tab.".into(),
                    );
                }
                let filename = app
                    .connection
                    .vault
                    .as_ref()
                    .ok_or("Select the vault to delete on the Vault tab.")?;
                confirmation = Some(format!(
                    "Permanently delete vault {filename}{}? All its entries and recovery data will be lost.",
                    if self.credentials.use_key && !self.credentials.keep_key {
                        " AND its external key file"
                    } else {
                        ""
                    }
                ));
                ServerCommand::Delete(Target::Vault {
                    key: self.credentials.value(false)?,
                    keep_key: self.credentials.keep_key,
                    vault_file: Some(filename.clone()),
                })
            }
            Action::Search => {
                revision = None;
                let nonempty = |value: &String| (!value.is_empty()).then(|| value.clone());
                ServerCommand::List(SearchFilter {
                    query: nonempty(&self.search.query),
                    name: nonempty(&self.search.name),
                    username: nonempty(&self.search.username),
                    url: nonempty(&self.search.url),
                    notes: (!self.search.notes.is_empty()).then(|| self.search.notes.clone()),
                    list: ListOptions {
                        kind: self.search.kind,
                        has_totp: self.search.has_otp,
                        weak: self.search.weak,
                        stale_days: optional_number(&self.audit.stale_days)?,
                        sort: self.search.sort,
                        descending: self.search.descending,
                    },
                })
            }
            Action::InstallHost | Action::UpdateHost | Action::Shortcut | Action::Completions => {
                return Err("This is a local desktop action.".into());
            }
        };
        if command.is_mutation() && app.recovery.id().is_some() {
            return Err(
                "Review the previous uncertain operation before making another change.".into(),
            );
        }
        if command.is_mutation() && app.editor.as_ref().is_some_and(|draft| draft.dirty) {
            return Err(
                "Save or discard the unsaved item edits before changing authenticators or using Tools.".into(),
            );
        }
        Ok(Prepared {
            action,
            command,
            revision,
            session: app.connection.session.clone(),
            confirmation,
        })
    }
    fn observe_otp(&mut self, code: &password_manager::protocol::AuthenticatorResponse) -> bool {
        let changed = self.otp.previous != code.code;
        self.otp.previous = code.code.clone();
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
        self.duo
            .seen
            .retain(|fingerprint| pending.contains(fingerprint));
        let mut fresh = false;
        for fingerprint in pending {
            fresh |= self.duo.seen.insert(fingerprint);
        }
        fresh
    }
    pub fn receive(&mut self, payload: ResponsePayload) {
        if let ResponsePayload::DuoRequests(requests) = payload {
            // Only the captured request context can bind a cache. Never infer it
            // from the current selection after the asynchronous read finishes.
            if let Some(target) = self.duo.inflight.take() {
                self.duo.result = Some(DuoRequests { target, requests });
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
        self.otp.result_target = if matches!(payload, ResponsePayload::Authenticator(_)) {
            self.otp.inflight.take()
        } else {
            None
        };
        self.history.result_target = if matches!(&payload, ResponsePayload::History(_)) {
            // History belongs to the initiating request, even if the visible
            // selection changes before the reply is delivered.
            let Some(target) = self.history.inflight.take() else {
                return;
            };
            Some(target)
        } else {
            self.history.inflight = None;
            None
        };
        self.result = Some(payload);
        self.show_results = true;
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
        if self.polling() {
            self.serial += 1;
            self.request_state = RequestState::Idle;
        }
        self.workspace.hide_secrets();
        self.workspace.reset_duo();
    }
    pub(super) fn fetch_selected_duo(&mut self) -> Task<super::Message> {
        // Opening an account is a one-shot read. Watching requires an explicit
        // toggle and remains bound to its own account across navigation.
        if self.tab != Tab::Vault
            || self.editor.is_some()
            || self.connection.session.is_none()
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
        if self.busy()
            || self.polling()
            || self.workspace.prepared.is_some()
            || self.recovery.id().is_some()
            || self.connection.session.is_none()
            || !self.connection.running
        {
            return Task::none();
        }
        let (action, target, seconds) = if let Some(target) = self.workspace.otp.watch.clone() {
            (Action::WatchOtp, target, 1)
        } else if let Some(target) = self.workspace.duo.watch.clone() {
            let seconds = match self.workspace.authenticator.duo_interval_seconds() {
                Ok(seconds) => seconds,
                Err(error) => {
                    self.workspace.reset_duo();
                    self.report_error(error);
                    return Task::none();
                }
            };
            (Action::Requests, target, seconds)
        } else {
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
                self.report_error(error);
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
        let Some(target) = self.workspace.otp.watch.clone() else {
            return Task::none();
        };
        if !target.current(self) || self.workspace.request_epoch != self.workspace.secret_epoch {
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
            && self.workspace.otp.copy
            && self.workspace.prepared.is_none()
            && self.recovery.id().is_none()
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
        let Some(target) = self.workspace.otp.watch.clone() else {
            return Task::none();
        };
        if !self.workspace.otp.copy
            || !target.current(self)
            || self.workspace.request_epoch != self.workspace.secret_epoch
            || self.workspace.prepared.is_some()
            || self.recovery.id().is_some()
        {
            return Task::none();
        }
        if matches!(
            self.workspace
                .authenticator
                .otp_timeout(self.conf.clipboard.timeout),
            Ok(None)
        ) {
            self.workspace.otp.copy = false;
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
                self.report_error(error);
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
        let Some(target) = self.workspace.duo.inflight.as_ref() else {
            return Task::none();
        };
        if !target.current(self) {
            self.workspace.duo.inflight = None;
            return Task::none();
        }
        let watching = self
            .workspace
            .duo
            .watch
            .as_ref()
            .is_some_and(|watch| watch.same_context(target));
        let notify = if let ResponsePayload::DuoRequests(requests) = &payload {
            watching && self.workspace.observe_duo(requests) && self.workspace.duo.notify
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
        if self.polling()
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
            self.request_state = RequestState::Idle;
        }
        match event {
            Event::ShowResults(show) => {
                self.workspace.show_results = show;
                return show_form();
            }
            Event::Section(section) => {
                self.workspace.show_results = false;
                self.workspace.hide_secrets();
                self.workspace.clear_history();
                self.workspace.section = section;
                self.workspace.result = None;
                self.workspace.prepared = None;
                return show_form();
            }
            Event::FileOperation(operation) => {
                self.workspace.files.file_operation = operation;
                if operation == FileOperation::Import && self.connection.session.is_none() {
                    self.workspace.files.import_new = true;
                }
                self.workspace.section = Section::Files;
                self.workspace.show_results = false;
                self.workspace.prepared = None;
                self.workspace.result = None;
                self.workspace.clear_inputs();
                return show_form();
            }
            Event::VaultOperation(operation) => {
                self.workspace.credentials.vault_operation = operation;
                self.workspace.prepared = None;
                self.workspace.clear_inputs();
            }
            Event::Shell(shell) => self.workspace.utilities.shell = shell,
            Event::Field(field, value) => self.workspace.edit(field, value),
            Event::Toggle(toggle, value) => {
                self.workspace.toggle(toggle, value);
                if matches!(toggle, Toggle::WatchOtp | Toggle::WatchDuo) && value {
                    let target = match WatchTarget::selected(self) {
                        Ok(target) => target,
                        Err(error) => {
                            self.stop_tool_watches();
                            self.report_error(error);
                            return Task::none();
                        }
                    };
                    let action = if matches!(toggle, Toggle::WatchOtp) {
                        let timeout = self
                            .workspace
                            .authenticator
                            .otp_timeout(self.conf.clipboard.timeout);
                        if let Err(error) = timeout.as_ref() {
                            self.workspace.hide_secrets();
                            self.notice = error.clone();
                            return Task::none();
                        }
                        if self.workspace.otp.copy && timeout.unwrap().is_none() {
                            self.workspace.hide_secrets();
                            self.notice =
                                "Set an OTP copy timeout greater than zero to watch and copy."
                                    .into();
                            return Task::none();
                        }
                        self.workspace.reset_duo();
                        self.workspace.otp.watch = Some(target.clone());
                        self.workspace.otp.previous.zeroize();
                        Action::WatchOtp
                    } else {
                        if let Err(error) = self.workspace.authenticator.duo_interval_seconds() {
                            self.workspace.reset_duo();
                            self.report_error(error);
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
                        self.workspace.duo.seen.clear();
                        self.workspace.duo.watch = Some(target.clone());
                        Action::Requests
                    };
                    return match self.workspace.prepare_for(action, self, Some(&target)) {
                        Ok(prepared) => self.execute_workflow(prepared),
                        Err(error) => {
                            self.stop_tool_watches();
                            self.report_error(error);
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
                self.workspace.files.policy = policy;
                self.workspace.prepared = None;
            }
            Event::Mode(mode) => {
                self.workspace.authenticator.mode = mode;
                self.workspace.prepared = None;
            }
            Event::Browser(browser) => self.workspace.browser.browser = browser,
            Event::Kind(kind) => self.workspace.search.kind = kind,
            Event::Sort(sort) => self.workspace.search.sort = sort,
            Event::HasOtp(has_otp) => self.workspace.search.has_otp = has_otp,
            Event::Pick(field, save) => {
                self.workspace.prepared = None;
                self.serial += 1;
                self.request_state = RequestState::Busy;
                return file_picker::pick_workflow_file(self.serial, field, save);
            }
            Event::ClearResult => {
                self.workspace.show_results = false;
                self.workspace.clear_history();
                self.workspace.result = None;
                self.workspace.prepared = None;
            }
            Event::NotificationFinished(result) => {
                if let Err(reason) = result {
                    self.notice = reason;
                }
            }
            Event::Cancel => {
                self.workspace.prepared = None;
                self.workspace.show_results = false;
            }
            Event::Confirm => {
                if let Some(prepared) = self.workspace.prepared.take() {
                    return self.execute_workflow(prepared);
                }
            }
            Event::Run(action) if action.local() => {
                if action == Action::Completions {
                    let path = match absolute(&self.workspace.files.path) {
                        Ok(path) => path,
                        Err(error) => {
                            self.report_error(error);
                            return Task::none();
                        }
                    };
                    let shell = self.workspace.utilities.shell;
                    return self.launch(Job::Local, move || {
                        backend::save_completions(shell, std::path::Path::new(&path))
                    });
                }
                let extension_id = self.workspace.browser.extension_id.clone();
                let browser = match self.workspace.browser.browser {
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
                    self.report_error(error);
                    if matches!(action, Action::WatchOtp | Action::CopyWatchedOtp) {
                        self.workspace.hide_secrets();
                    }
                }
            },
        }
        Task::none()
    }
    fn execute_workflow(&mut self, mut prepared: Prepared) -> Task<super::Message> {
        if prepared.session != self.connection.session {
            self.notice = "The vault session changed. Review this operation again.".into();
            return Task::none();
        }
        if prepared.command.is_mutation() && self.recovery.id().is_some() {
            self.notice =
                "Review the previous uncertain operation before making another change.".into();
            return Task::none();
        }
        if prepared.command.is_mutation() && self.editor.as_ref().is_some_and(|draft| draft.dirty) {
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
                        .history
                        .result_target
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
            self.workspace.history.inflight = context.clone();
        }
        if matches!(
            prepared.action,
            Action::ShowOtp(_) | Action::WatchOtp | Action::CopyWatchedOtp
        ) {
            self.workspace.otp.inflight = context.clone();
        }
        if prepared.action == Action::Requests {
            self.workspace.duo.inflight = context;
        }
        self.workspace.request_epoch = self.workspace.secret_epoch;
        self.workspace.last_watch = Instant::now();
        let command = std::mem::replace(&mut prepared.command, ServerCommand::Status);
        let passive = matches!(prepared.action, Action::WatchOtp | Action::Requests);
        let task = self.request(Job::Workflow(prepared.action), command, prepared.revision);
        if passive {
            self.request_state = RequestState::Polling;
        }
        task
    }
}
pub fn show_result() -> Task<super::Message> {
    show_form()
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
