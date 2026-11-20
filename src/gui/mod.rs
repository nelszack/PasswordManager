//! An Iced client of the existing server, never a second owner of vault state.
mod backend;
mod cloud;
mod connection;
mod discovery;
mod editor;
mod file_picker;
mod generator;
mod items;
mod model;
mod presentation;
mod settings;
mod state;
mod styles;
mod vault_names;
mod view;
mod website;
mod widgets;
mod workflows;

use backend::{Failure, Reply};
use iced::{Element, Subscription, Task, Theme, keyboard, widget::text_editor};
use model::Draft;
use password_manager::{
    client::AuthenticatedClient,
    config::Config,
    protocol::{OperationState, RequestEnvelope, ResponseCode, ResponsePayload},
    secret::SecretString,
    types::{
        ItemKind, ListOptions, PasswordType, SearchFilter, ServerCommand, SortField, Target,
        UnlockInfo,
    },
    vault::{ItemDetail, ItemSummary},
};
use settings::{Field as SettingsField, SettingsDraft, Toggle as SettingsToggle};
use state::{Editor, GeneratedSecret, Recovery};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use zeroize::Zeroize;

/// How often an idle desktop session checks server status.
const STATUS_INTERVAL: Duration = Duration::from_secs(2);
/// Safety poll while the server pushes changes (it also sends a heartbeat).
const SUBSCRIBED_STATUS_INTERVAL: Duration = Duration::from_secs(30);

pub fn run(conf: Config, client: AuthenticatedClient) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    crate::desktop::detach_private_console();
    #[cfg(target_os = "linux")]
    if std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return Err("No desktop display is available. Run pm --help for CLI commands.".into());
    }
    iced::application(
        move || App::boot(conf.clone(), client.clone()),
        App::update,
        App::view,
    )
    .title("Password Manager")
    .theme(App::theme)
    .scale_factor(App::scale_factor)
    .window(iced::window::Settings {
        size: iced::Size::new(1060.0, 760.0),
        exit_on_close_request: false,
        min_size: Some(iced::Size::new(480.0, 480.0)),
        icon: Some(
            iced::window::icon::from_rgba(
                include_bytes!("../../assets/password-manager-64.rgba").to_vec(),
                64,
                64,
            )
            .expect("embedded application icon must contain 64 x 64 RGBA pixels"),
        ),
        #[cfg(target_os = "linux")]
        platform_specific: iced::window::settings::PlatformSpecific {
            application_id: "com.passwordmanager.Pm".into(),
            ..Default::default()
        },
        ..Default::default()
    })
    .centered()
    .subscription(App::subscription)
    .run()
    .map_err(|error| format!("could not open the desktop interface: {error}"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tab {
    Vault,
    Generator,
    Settings,
    Tools,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FieldTarget {
    id: usize,
    revision: u64,
    index: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Job {
    Connect,
    Attach,
    DiscoverVaults,
    ReloadSettings,
    OpenSettings,
    /// Reload preferences (clipboard timeouts, generator defaults), then continue.
    Reload(Then),
    UsernameValue,
    UsernameCopied,
    OpenWebsite,
    VaultName,
    Status,
    List,
    SavedList,
    Item,
    RefreshItem(usize, ItemIntent),
    OpenItem(usize, ItemIntent),
    Reveal,
    Field(FieldTarget),
    FieldCopy,
    Unlock,
    Lock,
    Create,
    Save,
    SaveEditor,
    Delete,
    Copy,
    Stop,
    Reconcile,
    Acknowledge,
    Settings,
    CopyGenerated,
    ConflictReview,
    PickKey,
    PickFile(workflows::Field),
    Workflow(workflows::Action),
    Local,
    Cloud,
    CloudList,
    CloudConflicts,
    CloudResolve,
}

/// Work that must use freshly reloaded preferences, so a setting changed by the
/// CLI or another window applies to the very next action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Then {
    Generate,
    Save,
    SaveEditor,
    CopyGenerated,
    CopyItem,
    FetchUsername,
    CopyField(FieldTarget),
    Workflow(workflows::Action),
    WatchOtp,
    CopyWatchedOtp,
}

#[derive(Clone, Debug)]
enum Navigate {
    Select(usize),
    New,
    Close,
    Refresh,
    Connect(u16),
}

#[derive(Clone)]
enum Message {
    Tick(Instant),
    /// `true`: the server pushed a status record; `false`: the push stream ended.
    StatusPushed(bool),
    Cloud(password_manager::cloud::Action),
    CloudToken(SecretString),
    CloudVault(String),
    CloudChoice(u64, String, password_manager::cloud::Side),
    CloudChooseAll(password_manager::cloud::Side),
    ResolveCloud,
    SaveCloudToken,
    Finished(u64, Job, Arc<Result<Reply, Failure>>),
    Connect,
    RefreshVaults,
    ReloadSettings,
    ConnectionPort(String),
    UseConnectionPort,
    Tab(Tab),
    Search(String),
    Navigate(Navigate),
    Discard,
    KeepEditing,
    Vault(String),
    VaultName(String),
    RenameVault,
    CopyUsername,
    OpenWebsite(usize),
    Master(SecretString),
    ConfirmMaster(SecretString),
    KeyPath(SecretString),
    UnlockTimeout(String),
    BrowseKey,
    Creating(bool),
    Unlock,
    Create,
    Lock,
    Stop,
    Edit,
    Name(String),
    Username(String),
    Kind(ItemKind),
    Password(SecretString),
    ShowEditorSecret(bool),
    ReplacePassword(bool),
    CopyPolicy(model::ClipboardPolicy),
    AddField,
    TemplateValue(&'static str, bool, SecretString),
    FieldName(usize, String),
    FieldValue(usize, SecretString),
    FieldSecret(usize, bool),
    RemoveField(usize),
    MultilineSecret(bool),
    SecretEdit(text_editor::Action),
    Url(usize, String),
    AddUrl,
    RemoveUrl(usize),
    Notes(text_editor::Action),
    Save,
    SaveAndEdit,
    Reveal,
    RevealField(FieldTarget),
    HideField(FieldTarget),
    CopyField(FieldTarget),
    HideSecrets,
    Copy,
    Delete,
    CancelDelete,
    ConfirmDelete,
    UndoDelete,
    Reconcile,
    Acknowledge,
    GeneratorLength(String),
    Passphrase(bool),
    Words(String),
    Generate,
    CopyGenerated,
    ShowGenerated(bool),
    UseGenerated,
    ConfirmGenerated,
    CancelGenerated,
    ReviewConflict,
    ReapplyConflict,
    CloseRequested(iced::window::Id),
    ConfirmClose,
    CancelClose,
    SettingChanged(SettingsField, String),
    SettingToggled(SettingsToggle, bool),
    SaveSettings,
    ResetSettings,
    CancelResetSettings,
    ConfirmResetSettings,
    FocusNext(bool),
    FocusSearch,
    ScrollFocus(Vec<(iced::advanced::widget::Id, f32)>),
    DismissNotice,
    Resize(iced::Size),
    Disclosure(presentation::Disclosure),
    FilterKind(Option<ItemKind>),
    ItemPage(usize),
    PageInput(String),
    JumpItemPage,
    SortItems(bool),
    ScrollPane(String, f32),
    SettingsSection(presentation::SettingsSection),
    Appearance(password_manager::config::Appearance),
    InterfaceScale(u16),
    OpenTools(workflows::Section),
    OpenFileTool(workflows::FileOperation),
    ConfirmStop(bool),
    Workflow(workflows::Event),
    OpenToolItem(usize),
    OpenItemTools(usize),
    Generator(generator::Event),
}

impl std::fmt::Debug for Message {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Text-editor actions contain plaintext inserts, unlike SecretString.
        // Never let Iced diagnostics format credential or note input events.
        formatter
            .debug_struct("DesktopMessage")
            .field("variant", &std::mem::discriminant(self))
            .finish_non_exhaustive()
    }
}

struct Creation {
    password: SecretString,
    name: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum RequestState {
    #[default]
    Idle,
    Busy,
    Revealing,
    Polling,
    Passive,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ItemIntent {
    View,
    Edit,
}

struct App {
    connection: connection::State,
    generation: generator::State,
    cloud: cloud::State,
    names: vault_names::Names,
    ui: presentation::State,
    conf: Config,
    tab: Tab,
    items: Vec<ItemSummary>,
    query: String,
    item: Option<ItemDetail>,
    editor: Editor,
    delete_confirm: bool,
    reveal_until: Option<Instant>,
    serial: u64,
    request_state: RequestState,
    notice: String,
    warning: Option<String>,
    recovery: Recovery,
    settings: SettingsDraft,
    vault_revision: Option<u64>,
    items_revision: Option<u64>,
    confirm_reset_settings: bool,
    workspace: workflows::State,
}

impl App {
    fn new(conf: Config, client: AuthenticatedClient) -> Self {
        Self {
            connection: connection::State {
                connection_port: client.port.to_string(),
                client,
                connect_after_discovery: false,
                running: false,
                session: None,
                vaults: vec![],
                vault: conf.unlock.vault_id.clone(),
                master: SecretString::default(),
                confirmation: SecretString::default(),
                key_path: SecretString::default(),
                unlock_timeout: conf.unlock.timeout.to_string(),
                creating: false,
                select_created_vault: false,
                creation: None,
                last_status: Instant::now(),
                subscribed: false,
                status_stale: false,
            },
            generation: generator::State {
                length: conf.genpass.length.to_string(),
                passphrase: false,
                words: "6".into(),
                value: GeneratedSecret::default(),
                stats: String::new(),
                options: generator::Options::default(),
            },
            cloud: cloud::State {
                token: SecretString::default(),
                vaults: vec![],
                vault: None,
                review: None,
                choices: vec![],
            },
            ui: presentation::State::default(),
            names: vault_names::Names::default(),
            settings: SettingsDraft::from(&conf),
            vault_revision: None,
            items_revision: None,
            conf,
            tab: Tab::Vault,
            items: vec![],
            query: String::new(),
            item: None,
            editor: Editor::Closed,
            delete_confirm: false,
            reveal_until: None,
            serial: 0,
            request_state: RequestState::Idle,
            notice: "Connecting to the vault server…".into(),
            warning: None,
            recovery: Recovery::Clear,
            confirm_reset_settings: false,
            workspace: workflows::State::default(),
        }
    }

    fn boot(conf: Config, client: AuthenticatedClient) -> (Self, Task<Message>) {
        let mut app = Self::new(conf, client);
        app.connection.connect_after_discovery = true;
        let task = app.refresh_vaults();
        (app, task)
    }

    fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            iced::time::every(self.tick_interval()).map(Message::Tick),
            self.status_subscription(),
            iced::event::listen_with(|event, status, _| match event {
                iced::Event::Keyboard(keyboard::Event::KeyPressed { key, modifiers, .. }) => {
                    match key {
                        keyboard::Key::Named(keyboard::key::Named::Tab)
                            if status == iced::event::Status::Ignored =>
                        {
                            Some(Message::FocusNext(modifiers.shift()))
                        }
                        keyboard::Key::Named(keyboard::key::Named::Escape) => {
                            Some(Message::HideSecrets)
                        }
                        keyboard::Key::Character(c)
                            if modifiers.command() && c.eq_ignore_ascii_case("l") =>
                        {
                            Some(Message::Lock)
                        }
                        keyboard::Key::Character(c)
                            if modifiers.command()
                                && modifiers.shift()
                                && c.eq_ignore_ascii_case("c") =>
                        {
                            Some(Message::CopyUsername)
                        }
                        keyboard::Key::Character(c)
                            if modifiers.command()
                                && modifiers.shift()
                                && c.eq_ignore_ascii_case("o") =>
                        {
                            Some(Message::OpenWebsite(0))
                        }
                        keyboard::Key::Character(c) if modifiers.command() => match c
                            .to_lowercase()
                            .as_str()
                        {
                            "f" => Some(Message::FocusSearch),
                            "n" => Some(Message::Navigate(Navigate::New)),
                            "s" => Some(Message::Save),
                            "e" => Some(Message::Edit),
                            "r" => Some(Message::Navigate(Navigate::Refresh)),
                            "1" => Some(Message::Tab(Tab::Vault)),
                            "2" => Some(Message::Tab(Tab::Generator)),
                            "3" => Some(Message::Tab(Tab::Tools)),
                            "4" => Some(Message::Tab(Tab::Settings)),
                            "/" => Some(Message::Disclosure(presentation::Disclosure::Shortcuts)),
                            _ => None,
                        },
                        _ => None,
                    }
                }
                _ => None,
            }),
            iced::event::listen_with(|event, _, id| match event {
                iced::Event::Window(iced::window::Event::CloseRequested) => {
                    Some(Message::CloseRequested(id))
                }
                iced::Event::Window(iced::window::Event::Unfocused) => Some(Message::HideSecrets),
                iced::Event::Window(iced::window::Event::Resized(size)) => {
                    Some(Message::Resize(size))
                }
                _ => None,
            }),
        ])
    }

    /// One-second ticks only while something on screen counts down or
    /// expires; otherwise tick at the status-poll cadence to avoid idle redraws.
    /// A status request in flight does not count: its reply arrives as a
    /// message, so switching timers for it would only recreate the subscription.
    fn tick_interval(&self) -> Duration {
        let timed = self.busy()
            || self.connection.status_stale
            || self.reveal_until.is_some()
            || self.generation.value.deadline().is_some()
            || self.workspace.result_until.is_some()
            || self.workspace.otp.watch.is_some()
            || self.workspace.duo.watch.is_some()
            || self.workspace.duo.result.is_some();
        if timed {
            Duration::from_secs(1)
        } else {
            self.status_interval()
        }
    }
    /// Pushed status needs only an occasional safety poll.
    fn status_interval(&self) -> Duration {
        if self.connection.subscribed {
            SUBSCRIBED_STATUS_INTERVAL
        } else {
            STATUS_INTERVAL
        }
    }
    /// Pushed status from a running server; polling remains the fallback.
    fn status_subscription(&self) -> Subscription<Message> {
        if !self.connection.running {
            return Subscription::none();
        }
        Subscription::run_with(
            backend::EventSource {
                port: self.connection.client.port,
                token_path: self.connection.client.token_path.clone(),
            },
            backend::status_events,
        )
    }
    fn busy(&self) -> bool {
        matches!(
            self.request_state,
            RequestState::Busy | RequestState::Revealing
        )
    }
    fn polling(&self) -> bool {
        self.request_state == RequestState::Polling
    }
    fn revealing(&self) -> bool {
        self.request_state == RequestState::Revealing
    }

    fn launch(
        &mut self,
        job: Job,
        work: impl FnOnce() -> Result<Reply, Failure> + Send + 'static,
    ) -> Task<Message> {
        self.serial += 1;
        let serial = self.serial;
        // Passive status reads must not disable focused inputs or drop typing.
        // A user operation supersedes the poll via its newer serial number.
        self.request_state = match job {
            Job::Status => RequestState::Polling,
            Job::OpenWebsite => RequestState::Passive,
            Job::Reveal
            | Job::Field(_)
            | Job::Reload(Then::WatchOtp | Then::Workflow(workflows::Action::ShowOtp(true))) => {
                RequestState::Revealing
            }
            _ => RequestState::Busy,
        };
        if self.busy() {
            self.ui.progress_started = Some(Instant::now());
            self.ui.progress = match job {
                Job::Save | Job::SaveEditor => "Saving item…".into(),
                Job::Unlock => "Unlocking vault…".into(),
                Job::Create => "Creating encrypted vault…".into(),
                Job::ConflictReview => "Loading the latest version for comparison…".into(),
                Job::Settings => "Saving settings…".into(),
                Job::Reload(Then::Generate) => "Loading generation preferences…".into(),
                Job::Copy
                | Job::CopyGenerated
                | Job::FieldCopy
                | Job::Reload(Then::CopyGenerated | Then::CopyItem) => {
                    "Copying with timed clipboard cleanup…".into()
                }
                Job::Workflow(action) => format!("{}…", action.confirm_label()),
                Job::Connect | Job::Attach => "Connecting to the local vault service…".into(),
                _ => "Working…".into(),
            };
        }
        if !self.polling() {
            self.ui.notice_error = false;
        }
        Task::perform(
            async move {
                tokio::task::spawn_blocking(work).await.unwrap_or_else(|_| {
                    Err(Failure::from(
                        "The desktop operation could not finish. Inspect the vault before \
                         retrying any change."
                            .to_owned(),
                    ))
                })
            },
            move |result| Message::Finished(serial, job, Arc::new(result)),
        )
    }

    fn reload_then(&mut self, then: Then) -> Task<Message> {
        self.launch(Job::Reload(then), backend::reload_settings)
    }

    fn resume(&mut self, then: Then) -> Task<Message> {
        match then {
            Then::Generate => self.generate(),
            Then::Save => self.save_item(Job::Save),
            Then::SaveEditor => self.save_item(Job::SaveEditor),
            Then::CopyGenerated => self.copy_generated(),
            Then::CopyItem => self.copy_item(),
            Then::FetchUsername => self.fetch_username(),
            Then::CopyField(target) => match self.custom_field_command(target, true) {
                Ok((command, revision)) => self.request(Job::FieldCopy, command, Some(revision)),
                Err(error) => {
                    self.report_error(error);
                    Task::none()
                }
            },
            Then::Workflow(action) => self.workflow(workflows::Event::Run(action)),
            Then::WatchOtp => {
                self.workflow(workflows::Event::Toggle(workflows::Toggle::WatchOtp, true))
            }
            Then::CopyWatchedOtp => self.copy_watched_otp(),
        }
    }

    fn connect(&mut self) -> Task<Message> {
        let client = self.connection.client.clone();
        self.connection.last_status = Instant::now();
        self.launch(Job::Connect, move || backend::connect(&client))
    }

    fn request(
        &mut self,
        job: Job,
        command: ServerCommand,
        revision: Option<u64>,
    ) -> Task<Message> {
        let mut envelope = RequestEnvelope::new(command);
        if !matches!(
            job,
            Job::Connect
                | Job::Attach
                | Job::Status
                | Job::Lock
                | Job::Unlock
                | Job::Create
                | Job::Reconcile
                | Job::Stop
        ) {
            envelope.expected_session = self.connection.session.clone();
        }
        envelope.expected_revision = revision;
        let client = self.connection.client.clone();
        self.launch(job, move || backend::request(&client, envelope))
    }

    fn status(&mut self) -> Task<Message> {
        self.connection.last_status = Instant::now();
        self.connection.status_stale = false;
        self.request(Job::Status, ServerCommand::Status, None)
    }

    fn hide_secrets(&mut self) {
        self.ui.editor_show_secret = false;
        self.workspace.hide_secrets();
        if let Some(draft) = self.editor.as_mut() {
            // Multiline input is deliberately visible while editing. Focus
            // loss and Escape must mask it just like a revealed stored secret.
            draft.multiline = false;
            draft.secret_editor = text_editor::Content::new();
        }
        if self.revealing() {
            // Focus loss/Escape can arrive before a reveal or OTP settings
            // preflight completes. Neither may dispatch new secret work later.
            self.serial += 1;
            self.request_state = RequestState::Idle;
        }
        self.reveal_until = None;
        self.generation.value.set_visible(false);
        if let Some(item) = self.item.as_mut() {
            item.password = None;
            for field in &mut item.fields {
                if field.secret {
                    field.value = None;
                }
            }
        }
    }

    fn clear_vault(&mut self) {
        self.cloud.review = None;
        self.cloud.choices.clear();
        self.hide_secrets();
        self.connection.session = None;
        self.workspace.clear_vault();
        self.replace_items(Vec::new());
        self.items_revision = None;
        self.query.zeroize();
        self.ui.item_page = 0;
        self.ui.kind = None;
        self.ui.undo_trash = None;
        self.ui.active_vault = None;
        self.ui.saved_item = None;

        self.ui.transfer_generated = false;
        self.ui.confirm_stop = false;
        self.item = None;
        self.editor = Editor::Closed;
        self.delete_confirm = false;
        self.connection.creation = None;
        self.connection.master.zeroize();
        self.connection.confirmation.zeroize();
        self.connection.key_path.zeroize();
        self.generation.value.clear();
        self.generation.stats.clear();
        self.generation.options.check.zeroize();
        self.generation.options.assessment.clear();
    }

    fn cancel_passive_read(&mut self) {
        if self.polling() {
            self.serial += 1;
            self.request_state = RequestState::Idle;
        }
    }

    fn report_error(&mut self, message: impl Into<String>) {
        self.notice = message.into();
        self.ui.notice_error = true;
    }

    fn writes_allowed(&self) -> bool {
        !self.busy() && self.recovery.id().is_none()
    }

    fn copying_allowed(&self) -> bool {
        self.writes_allowed() && self.conf.clipboard.timeout > 0
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        if matches!(
            &message,
            Message::Name(_)
                | Message::Username(_)
                | Message::Kind(_)
                | Message::Password(_)
                | Message::ReplacePassword(_)
                | Message::AddField
                | Message::FieldName(..)
                | Message::FieldValue(..)
                | Message::TemplateValue(..)
                | Message::FieldSecret(..)
                | Message::RemoveField(_)
                | Message::MultilineSecret(_)
                | Message::SecretEdit(_)
                | Message::Url(..)
                | Message::AddUrl
                | Message::RemoveUrl(_)
                | Message::Notes(_)
                | Message::Generate
        ) && self.editor.is_some()
            && !self.busy()
        {
            self.workspace.prepared = None;
        }
        match message {
            Message::CloseRequested(id) => {
                if self.busy()
                    || self.editor.as_ref().is_some_and(|draft| draft.dirty)
                    || self.settings.is_dirty()
                {
                    self.ui.confirm_close = Some(id);
                    self.hide_secrets();
                    return iced::widget::operation::focus("keep-window-open");
                } else {
                    return iced::window::close(id);
                }
            }
            Message::CancelClose => self.ui.confirm_close = None,
            Message::ConfirmClose => {
                if let Some(id) = self.ui.confirm_close.take() {
                    return iced::window::close(id);
                }
            }
            message @ (Message::Cloud(..)
            | Message::CloudChoice(..)
            | Message::CloudChooseAll(..)
            | Message::ResolveCloud
            | Message::CloudToken(..)
            | Message::CloudVault(..)
            | Message::SaveCloudToken) => return self.update_cloud(message),
            Message::Finished(serial, job, result) => {
                if serial != self.serial {
                    return Task::none();
                }
                self.request_state = RequestState::Idle;
                let result = Arc::try_unwrap(result).unwrap_or_else(|shared| (*shared).clone());
                return match result {
                    Ok(reply) => self.complete(job, reply),
                    Err(error) => {
                        if job == Job::SavedList {
                            self.ui.saved_item = None;
                        }
                        if matches!(job, Job::Create | Job::Unlock) {
                            self.connection.creation = None;
                        }
                        self.report_error(error.message);
                        if matches!(job, Job::Workflow(_)) {
                            self.stop_tool_watches();
                        }
                        if let Some(id) = error.uncertain_operation {
                            self.recovery = Recovery::AwaitingOutcome(id);

                            self.notice.push_str(
                                " The change may have completed. Check its outcome before making \
                                 another change.",
                            );
                            self.editor = Editor::Closed;
                            self.hide_secrets();
                        }
                        if matches!(job, Job::Connect | Job::Attach | Job::Status) {
                            self.connection.running = false;
                            self.clear_vault();
                        }
                        if job == Job::DiscoverVaults && self.connection.connect_after_discovery {
                            self.connection.connect_after_discovery = false;
                            return self.connect();
                        }
                        Task::none()
                    }
                };
            }
            Message::StatusPushed(true) => {
                self.connection.subscribed = true;
                if self.connection.running && !self.busy() && !self.polling() {
                    return self.status();
                }
                // Refresh once the current request finishes (next tick).
                self.connection.status_stale = true;
            }
            Message::StatusPushed(false) => self.connection.subscribed = false,
            Message::Tick(now) => {
                if self
                    .workspace
                    .result_until
                    .is_some_and(|deadline| now >= deadline)
                {
                    self.workspace.result = None;
                    self.workspace.result_until = None;
                }
                if self.reveal_until.is_some_and(|deadline| now >= deadline) {
                    self.hide_secrets();
                }
                if self.generation.value.expire(now) {
                    self.generation.stats.clear();
                    self.ui.transfer_generated = false;
                    if self.notice.starts_with("New secret ready.") {
                        self.notice = "Generated secret cleared after 60 seconds. Generate \
                                       another when you need it."
                            .into();
                    }
                }
                if !self.busy()
                    && !self.polling()
                    && now.saturating_duration_since(self.connection.last_status)
                        < Duration::from_secs(2)
                {
                    let task = self.poll_tool_watches(now);
                    if self.polling() || self.busy() {
                        return task;
                    }
                }
                // Allow timer jitter so an idle tick at the poll cadence is not skipped.
                let interval = self.status_interval();
                if self.connection.running
                    && !self.busy()
                    && !self.polling()
                    && (self.connection.status_stale
                        || now.duration_since(self.connection.last_status)
                            >= interval - Duration::from_millis(250))
                {
                    return self.status();
                }
            }
            Message::Lock if self.connection.running => {
                // Invalidate older completions immediately, even if a request is in flight.
                self.clear_vault();
                self.notice.clear();
                return self.request(Job::Lock, ServerCommand::Lock(true), None);
            }
            Message::HideSecrets => self.hide_secrets(),
            Message::FocusNext(backwards) => {
                let focus = if backwards {
                    iced::widget::operation::focus_previous()
                } else {
                    iced::widget::operation::focus_next()
                };
                return focus.chain(widgets::ensure_focus_visible());
            }
            Message::ScrollFocus(offsets) => {
                return Task::batch(offsets.into_iter().map(|(id, delta)| {
                    iced::widget::operation::scroll_by(
                        id,
                        iced::widget::operation::AbsoluteOffset { x: 0.0, y: delta },
                    )
                }));
            }
            Message::ScrollPane(id, y) => {
                return iced::widget::operation::scroll_by(
                    id,
                    iced::widget::operation::AbsoluteOffset { x: 0.0, y },
                );
            }
            Message::Resize(size) => {
                self.ui.width = size.width;
                self.ui.height = size.height;
            }
            Message::DismissNotice => {
                self.ui.undo_trash = None;
                self.notice.clear();
                self.ui.notice_error = false;
            }
            _ if self.busy() => return Task::none(),
            Message::Disclosure(section) => {
                use presentation::Disclosure;
                let expanded = match section {
                    Disclosure::Unlock => &mut self.ui.unlock_advanced,
                    Disclosure::Editor => &mut self.ui.editor_advanced,
                    Disclosure::Authenticators => &mut self.ui.editor_authenticators,
                    Disclosure::Generator => &mut self.ui.generator_advanced,
                    Disclosure::Shortcuts => &mut self.ui.shortcuts,
                };
                *expanded = !*expanded;
                if !*expanded {
                    if matches!(section, Disclosure::Unlock) {
                        self.connection.key_path.zeroize();
                    }
                    self.hide_secrets();
                }
            }
            message @ (Message::CancelDelete
            | Message::ConfirmDelete
            | Message::Copy
            | Message::CopyField(..)
            | Message::CopyUsername
            | Message::Delete
            | Message::FilterKind(..)
            | Message::HideField(..)
            | Message::ItemPage(..)
            | Message::JumpItemPage
            | Message::Navigate(..)
            | Message::OpenWebsite(..)
            | Message::PageInput(..)
            | Message::ReapplyConflict
            | Message::Reveal
            | Message::RevealField(..)
            | Message::ReviewConflict
            | Message::Search(..)
            | Message::SortItems(..)
            | Message::UndoDelete) => return self.update_items(message),
            Message::ConfirmStop(value) => self.ui.confirm_stop = value,
            message @ (Message::SettingsSection(..)
            | Message::Appearance(..)
            | Message::InterfaceScale(..)
            | Message::SettingChanged(..)
            | Message::SettingToggled(..)
            | Message::SaveSettings
            | Message::ResetSettings
            | Message::CancelResetSettings
            | Message::ConfirmResetSettings) => return self.update_settings(message),
            Message::FocusSearch if self.connection.session.is_some() => {
                self.tab = Tab::Vault;
                self.hide_secrets();
                if self.compact() && (self.editor.is_some() || self.item.is_some()) {
                    return self
                        .navigate(Navigate::Close)
                        .chain(iced::widget::operation::focus("vault-search"));
                }
                return iced::widget::operation::focus("vault-search");
            }
            Message::OpenFileTool(operation) => {
                self.ui.undo_trash = None;
                self.hide_secrets();
                self.cancel_passive_read();
                self.tab = Tab::Tools;
                return self.workflow(workflows::Event::FileOperation(operation));
            }
            Message::OpenTools(section) => {
                self.ui.undo_trash = None;
                self.hide_secrets();
                self.cancel_passive_read();
                self.tab = Tab::Tools;
                return self.workflow(workflows::Event::Section(section));
            }
            Message::Workflow(workflows::Event::Run(action))
                if matches!(
                    action,
                    workflows::Action::ShowOtp(true)
                        | workflows::Action::Import
                        | workflows::Action::PreviewImport
                ) =>
            {
                return self.reload_then(Then::Workflow(action));
            }
            Message::Workflow(workflows::Event::Toggle(workflows::Toggle::WatchOtp, true)) => {
                return self.reload_then(Then::WatchOtp);
            }
            Message::Workflow(event) => return self.workflow(event),
            message @ (Message::Generator(..)
            | Message::GeneratorLength(..)
            | Message::Passphrase(..)
            | Message::Words(..)
            | Message::Generate
            | Message::ShowGenerated(..)
            | Message::UseGenerated
            | Message::CancelGenerated
            | Message::ConfirmGenerated
            | Message::CopyGenerated) => return self.update_generator(message),
            Message::OpenToolItem(id) => {
                self.tab = Tab::Vault;
                return self.navigate(Navigate::Select(id));
            }
            Message::OpenItemTools(id) => {
                self.ui.undo_trash = None;
                self.hide_secrets();
                self.cancel_passive_read();
                self.tab = Tab::Tools;
                self.workspace.section = workflows::Section::Recovery;
                self.workspace.selected =
                    self.items
                        .iter()
                        .find(|item| item.id == id)
                        .map(|item| workflows::Choice {
                            id,
                            label: format!("{} · {}", item.id, item.name),
                        });
                self.workspace.result = None;
                self.workspace.prepared = None;
                return workflows::show_form();
            }
            message @ (Message::Connect
            | Message::RefreshVaults
            | Message::ReloadSettings
            | Message::ConnectionPort(..)
            | Message::UseConnectionPort
            | Message::Vault(..)
            | Message::Master(..)
            | Message::ConfirmMaster(..)
            | Message::KeyPath(..)
            | Message::UnlockTimeout(..)
            | Message::BrowseKey
            | Message::Creating(..)
            | Message::Unlock
            | Message::Create
            | Message::Stop) => return self.update_connection(message),
            Message::Tab(tab) => {
                if tab != self.tab {
                    self.ui.undo_trash = None;
                }
                self.hide_secrets();
                self.cancel_passive_read();
                self.workspace.prepared = None;
                self.tab = tab;
                if tab == Tab::Generator && self.generation.value.is_empty() {
                    self.preview_generated();
                }
                if tab == Tab::Vault && self.editor.is_none() {
                    if let Some(item) = &self.item {
                        self.workspace.selected = Some(workflows::Choice {
                            id: item.id,
                            label: format!("{} · {}", item.id, item.name),
                        });
                    }
                    return self.fetch_selected_duo();
                }
                if tab == Tab::Settings {
                    if self.ui.settings_section == presentation::SettingsSection::Security
                        && let Some(id) = &self.connection.vault
                    {
                        self.ui.vault_name = self.names.label(id, &self.connection.vaults);
                    }
                    return self.launch(Job::OpenSettings, backend::reload_settings);
                }
            }
            Message::Discard => {
                let destination = self.editor.take_deferred();
                self.editor = Editor::Closed;
                if let Some(destination) = destination {
                    return self.navigate(destination);
                }
            }
            Message::KeepEditing => {
                self.editor.take_deferred();
            }
            Message::VaultName(value) => self.ui.vault_name = value,
            Message::RenameVault if self.writes_allowed() => {
                if let Some(id) = self.connection.vault.clone() {
                    let label = self.ui.vault_name.clone();
                    return self.launch(Job::VaultName, move || {
                        backend::save_vault_name(&id, &label)
                    });
                }
            }
            message @ (Message::Edit
            | Message::Name(..)
            | Message::TemplateValue(..)
            | Message::AddField
            | Message::FieldName(..)
            | Message::FieldValue(..)
            | Message::FieldSecret(..)
            | Message::RemoveField(..)
            | Message::ShowEditorSecret(..)
            | Message::MultilineSecret(..)
            | Message::SecretEdit(..)
            | Message::Username(..)
            | Message::Kind(..)
            | Message::Password(..)
            | Message::CopyPolicy(..)
            | Message::ReplacePassword(..)
            | Message::Url(..)
            | Message::AddUrl
            | Message::RemoveUrl(..)
            | Message::Notes(..)) => return self.update_editor(message),
            Message::SaveAndEdit
                if self.writes_allowed()
                    && self.editor.as_ref().is_some_and(|draft| draft.id.is_some()) =>
            {
                self.workspace.prepared = None;
                return self.reload_then(Then::SaveEditor);
            }
            Message::Save if self.writes_allowed() && self.tab == Tab::Settings => {
                return self.update(Message::SaveSettings);
            }
            Message::Save
                if self.writes_allowed() && self.tab == Tab::Vault && self.editor.is_some() =>
            {
                self.workspace.prepared = None;
                return self.reload_then(Then::Save);
            }
            Message::Reconcile => {
                if let Some(id) = self.recovery.id() {
                    return self.request(
                        Job::Reconcile,
                        ServerCommand::OperationStatus(id.clone()),
                        None,
                    );
                }
            }
            Message::Acknowledge if self.recovery.reviewed() => {
                if let Some(id) = self.recovery.id().cloned() {
                    let client = self.connection.client.clone();
                    return self
                        .launch(Job::Acknowledge, move || backend::acknowledge(&client, &id));
                }
            }
            _ => {}
        }
        Task::none()
    }

    fn complete(&mut self, job: Job, reply: Reply) -> Task<Message> {
        if job != Job::Status {
            self.ui.notice_error = false;
        }
        let reply = match reply {
            Reply::Created { reply, names } => {
                self.names = names;
                *reply
            }
            reply => reply,
        };
        let Reply::Server {
            response,
            vaults,
            pending,
        } = reply
        else {
            match reply {
                Reply::Settings {
                    conf,
                    restart_required,
                } => {
                    let restart_required = restart_required
                        || self.connection.running && conf.recovery != self.conf.recovery;
                    if !self.connection.running
                        && conf.server.port != self.conf.server.port
                        && self.connection.client.port == self.conf.server.port
                    {
                        self.reset_connection(conf.server.port);
                    }
                    if self.connection.session.is_none()
                        && conf.unlock.vault_id != self.conf.unlock.vault_id
                    {
                        self.connection.vault = conf.unlock.vault_id.clone();
                    }
                    self.settings = SettingsDraft::from(&conf);
                    self.connection.unlock_timeout = conf.unlock.timeout.to_string();
                    self.generation.length = conf.genpass.length.to_string();
                    self.generation.stats = if self.generation.options.stats_enabled(&conf)
                        && !self.generation.value.is_empty()
                    {
                        password_manager::password::password_strength_output(
                            self.generation.value.expose(),
                        )
                    } else {
                        String::new()
                    };
                    self.conf = conf;
                    self.notice = if restart_required {
                        "Settings saved. Restart the server to apply recovery settings. The lock \
                         timeout applies on the next unlock."
                    } else {
                        "Settings saved. The lock timeout applies on the next unlock."
                    }
                    .into();
                }
                Reply::Vaults { vaults, names } => {
                    self.names = names;
                    self.apply_vaults(vaults);
                    if self.connection.connect_after_discovery {
                        self.connection.connect_after_discovery = false;
                        return self.connect();
                    }
                }
                Reply::Configuration(conf) => {
                    self.apply_configuration(conf);
                    if job != Job::ReloadSettings && self.notice == "Settings reloaded." {
                        self.notice.clear();
                    }
                    if let Job::Reload(then) = job {
                        return self.resume(then);
                    }
                }
                Reply::Copied => {
                    self.notice = if job == Job::UsernameCopied {
                        "Username copied. The clipboard will clear automatically."
                    } else {
                        "Generated value copied with timed clipboard cleanup."
                    }
                    .into();
                }
                Reply::Names(names) => {
                    self.names = names;
                    self.notice = "Vault name saved on this device.".into();
                }
                Reply::WebsiteOpened => {
                    self.notice = "Website opened in your default browser.".into()
                }
                Reply::Acknowledged => {
                    self.recovery = Recovery::Clear;

                    self.notice =
                        "Previous outcome acknowledged. You can make a new change.".into();
                    return self.status();
                }
                Reply::KeyFile(Some(path)) => {
                    self.connection.key_path = path;
                    self.connection.master.zeroize();
                    self.notice.clear();
                }
                Reply::PickedFile(field, Some(path)) => self.workspace.edit(field, path),
                Reply::Local(message) if job == Job::Local => self.notice = message,
                Reply::Local(message) => self.workspace.receive(ResponsePayload::Message(message)),
                _ => {}
            }
            return Task::none();
        };
        let response = *response;
        if self.recovery.id().is_none() {
            self.recovery = pending
                .first()
                .cloned()
                .map_or(Recovery::Clear, Recovery::AwaitingOutcome);
        }
        if let Some(receipt) = &response.operation
            && receipt.state == OperationState::CommittedDurabilityUnknown
        {
            self.recovery = Recovery::AwaitingOutcome(receipt.operation_id.clone());
        }
        let incomplete_audit = job == Job::Workflow(workflows::Action::Audit)
            && response.code == ResponseCode::Failure as i32
            && matches!(response.payload, ResponsePayload::Audit(_));
        if incomplete_audit
            && (self.connection.session.is_none() || self.connection.session != response.session_id)
        {
            self.clear_vault();
            self.notice =
                "The vault session changed. Unlock or reopen the vault to continue.".into();
            return self.status();
        }
        let audit_warning = incomplete_audit.then(|| response.error_message());
        if incomplete_audit {
            self.hide_secrets();
        }
        if response.code != ResponseCode::Success as i32 && !incomplete_audit {
            if job == Job::SavedList {
                self.ui.saved_item = None;
            }
            if matches!(job, Job::Create | Job::Unlock) {
                self.connection.creation = None;
            }
            self.report_error(response.error_message());
            self.hide_secrets();
            if response.code == ResponseCode::Conflict as i32 {
                self.stop_tool_watches();
                self.workspace.prepared = None;
                if self.connection.session.is_some()
                    && self.connection.session == response.session_id
                    && self.editor.is_some()
                    && self.item.is_some()
                {
                    self.editor.require_review();
                    self.notice.push_str(
                        " Your unsaved edits are kept. Review the latest item before reapplying \
                         them.",
                    );
                } else {
                    self.clear_vault();
                    self.notice
                        .push_str(" The session changed. Unlock the vault again.");
                }
            }
            if matches!(job, Job::Connect | Job::Attach | Job::Status) {
                self.connection.running = false;
                self.clear_vault();
                return Task::none();
            }
            return self.status();
        }
        if matches!(job, Job::Connect | Job::Attach | Job::Status) {
            return self.complete_status(job, response, vaults);
        }
        // A lock or another client switching vaults invalidates every selection.
        if !matches!(
            job,
            Job::Unlock | Job::Lock | Job::Create | Job::Stop | Job::Reconcile
        ) && !matches!(job, Job::Workflow(action) if action.changes_vault())
            && self.connection.session != response.session_id
        {
            self.clear_vault();
            self.notice =
                "The vault session changed. Unlock or reopen the vault to continue.".into();
            return self.status();
        }
        let changed_id = response
            .changes
            .as_ref()
            .and_then(|changes| changes.items.first())
            .map(|item| item.id);
        let incremental = response
            .changes
            .as_ref()
            .is_some_and(|changes| self.apply_item_changes(changes));
        if matches!(job, Job::List | Job::SavedList | Job::RefreshItem(..))
            && matches!(response.payload, ResponsePayload::ItemPage(_))
        {
            self.items_revision = response.vault_revision;
            self.vault_revision = response.vault_revision.or(self.vault_revision);
        }
        match (job, response.payload) {
            (
                job @ (Job::CloudList | Job::CloudConflicts | Job::CloudResolve | Job::Cloud),
                payload,
            ) => {
                return self.complete_cloud(job, payload);
            }
            (Job::Workflow(action), payload) => {
                return self.complete_workflow(
                    action,
                    payload,
                    response.session_id,
                    audit_warning,
                    incremental,
                );
            }
            (
                job @ (Job::ConflictReview
                | Job::Copy
                | Job::Delete
                | Job::Field(..)
                | Job::FieldCopy
                | Job::Item
                | Job::List
                | Job::OpenItem(..)
                | Job::RefreshItem(..)
                | Job::Reveal
                | Job::Save
                | Job::SaveEditor
                | Job::SavedList
                | Job::UsernameValue),
                payload,
            ) => {
                return self.complete_item(job, payload, incremental, changed_id);
            }
            (Job::Reconcile, ResponsePayload::Operation(receipt)) => {
                match receipt.state {
                    OperationState::Committed | OperationState::Failed => {
                        self.recovery = Recovery::Clear;

                        self.notice = if receipt.state == OperationState::Committed {
                            "The previous change completed. Vault contents have been refreshed."
                        } else {
                            "The previous change failed. Review the vault before trying again."
                        }
                        .into();
                    }
                    OperationState::Pending => {
                        self.notice =
                            "The previous operation is still running. Check again shortly.".into()
                    }
                    OperationState::Unknown | OperationState::CommittedDurabilityUnknown => {
                        self.recovery = Recovery::AwaitingAcknowledgement(receipt.clone());
                        self.notice = "The previous outcome or storage durability is uncertain. \
                                       Inspect the vault before acknowledging it; the operation \
                                       will not be retried."
                            .into();
                    }
                }
                if self.connection.session.is_some() {
                    return self.navigate(Navigate::Refresh);
                }
                return self.status();
            }
            (Job::Stop, _) => {
                self.clear_vault();
                self.connection.running = false;
                self.notice = "Server stopped.".into();
            }
            (Job::Create | Job::Unlock | Job::Lock, _) => {
                let known = if job == Job::Unlock {
                    self.connection
                        .vault
                        .clone()
                        .zip(response.session_id.clone())
                } else {
                    None
                };
                let creation = if job == Job::Create && self.recovery.id().is_none() {
                    self.connection.creation.take()
                } else {
                    None
                };
                self.clear_vault();
                self.connection.creation = creation;
                self.ui.active_vault = known;
                self.connection.creating = false;
                if job == Job::Create {
                    self.connection.vault = None;
                    self.connection.select_created_vault = true;
                }
                self.notice = if job == Job::Create {
                    if self.connection.creation.is_some() {
                        "Opening your new vault…".into()
                    } else {
                        "Vault created. Select it and unlock to continue.".into()
                    }
                } else {
                    String::new()
                };
                return self.status();
            }
            _ => {
                self.notice =
                    "The server returned an unexpected response. Refresh the vault.".into()
            }
        }
        Task::none()
    }

    fn view(&self) -> Element<'_, Message> {
        view::view(self)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod render_tests;
