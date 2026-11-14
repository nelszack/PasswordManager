//! An Iced client of the existing server, never a second owner of vault state.
mod backend;
mod cloud;
mod connection;
mod discovery;
mod editor;
mod file_picker;
mod generator;
mod model;
mod presentation;
mod settings;
mod state;
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
    GenerateDefaults,
    SaveDefaults,
    SaveEditorDefaults,
    CopyDefaults,
    ItemCopyDefaults,
    UsernameDefaults,
    UsernameValue,
    UsernameCopied,
    OpenWebsite,
    VaultName,
    FieldCopyDefaults(FieldTarget),
    WorkflowDefaults(workflows::Action),
    WatchOtpDefaults,
    WatchCopyDefaults,
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
            iced::time::every(Duration::from_secs(1)).map(Message::Tick),
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
            | Job::WatchOtpDefaults
            | Job::WorkflowDefaults(workflows::Action::ShowOtp(true)) => RequestState::Revealing,
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
                Job::GenerateDefaults => "Loading generation preferences…".into(),
                Job::Copy
                | Job::CopyGenerated
                | Job::FieldCopy
                | Job::CopyDefaults
                | Job::ItemCopyDefaults => "Copying with timed clipboard cleanup…".into(),
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
                tokio::task::spawn_blocking(work).await.unwrap_or_else(|_| Err(Failure::from("The desktop operation could not finish. Inspect the vault before retrying any change.".to_owned())))
            },
            move |result| Message::Finished(serial, job, Arc::new(result)),
        )
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
        self.request(Job::Status, ServerCommand::Status, None)
    }

    fn load_items(&mut self) -> Task<Message> {
        self.load_items_for(Job::List)
    }

    fn load_items_for(&mut self, job: Job) -> Task<Message> {
        self.request(
            job,
            ServerCommand::List(SearchFilter {
                list: ListOptions {
                    sort: SortField::Name,
                    ..Default::default()
                },
                ..Default::default()
            }),
            None,
        )
    }

    fn open_item(&mut self, id: usize, intent: ItemIntent, revision: Option<u64>) -> Task<Message> {
        self.request(
            Job::OpenItem(id, intent),
            ServerCommand::ManagementItem { id, reveal: false },
            revision,
        )
    }

    fn refresh_item(&mut self, id: usize, intent: ItemIntent, incremental: bool) -> Task<Message> {
        if intent == ItemIntent::Edit {
            self.hide_secrets();
            self.editor = Editor::Closed;
            self.workspace.prepared = None;
            self.workspace.clear_inputs();
        }
        self.item = None;
        if incremental {
            self.open_item(id, intent, None)
        } else {
            self.load_items_for(Job::RefreshItem(id, intent))
        }
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

    fn navigate(&mut self, destination: Navigate) -> Task<Message> {
        if self.editor.as_ref().is_some_and(|draft| draft.dirty) {
            self.editor.defer(destination);
            return iced::widget::operation::focus("keep-editing");
        }
        self.hide_secrets();
        self.cancel_passive_read();
        self.notice.clear();
        self.ui.undo_trash = None;
        self.delete_confirm = false;
        self.workspace.prepared = None;
        self.workspace.clear_inputs();
        self.editor = Editor::Closed;

        self.item = None;
        match destination {
            Navigate::Select(id) => {
                let revision = self
                    .items
                    .iter()
                    .find(|item| item.id == id)
                    .map(|item| item.revision);
                self.request(
                    Job::Item,
                    ServerCommand::ManagementItem { id, reveal: false },
                    revision,
                )
            }
            Navigate::New => {
                self.ui.editor_advanced = false;
                self.ui.editor_authenticators = false;
                self.editor = Editor::new(Draft::default());
                iced::widget::operation::focus("item-name")
            }
            Navigate::Close => Task::none(),
            Navigate::Refresh => self.load_items(),
            Navigate::Connect(port) => {
                self.reset_connection(port);
                self.notice = format!("Connecting to port {port}…");
                let client = self.connection.client.clone();
                self.launch(Job::Attach, move || backend::attach(&client))
            }
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

                            self.notice.push_str(" The change may have completed. Check its outcome before making another change.");
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
                        self.notice = "Generated secret cleared after 60 seconds. Generate another when you need it.".into();
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
                if self.connection.running
                    && !self.busy()
                    && !self.polling()
                    && now.duration_since(self.connection.last_status) >= Duration::from_secs(2)
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
            Message::FilterKind(kind) => {
                self.ui.kind = kind;
                self.ui.item_page = 0;
            }
            Message::ItemPage(page) => {
                self.ui.item_page = page;
                self.ui.page_input.clear();
            }
            Message::PageInput(value) => self.ui.page_input = value,
            Message::SortItems(reverse) => {
                self.ui.reverse_items = reverse;
                self.ui.item_page = 0;
                self.ui.page_input.clear();
            }
            Message::JumpItemPage => {
                let pages = self.matching_items().len().div_ceil(50).max(1);
                if let Ok(page) = self.ui.page_input.parse::<usize>()
                    && page > 0
                    && page <= pages
                {
                    self.ui.item_page = page - 1;
                    self.ui.page_input.clear();
                } else {
                    self.report_error(format!("Enter a page number from 1 to {pages}."));
                }
            }

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
                return self.launch(Job::WorkflowDefaults(action), backend::reload_settings);
            }
            Message::Workflow(workflows::Event::Toggle(workflows::Toggle::WatchOtp, true)) => {
                return self.launch(Job::WatchOtpDefaults, backend::reload_settings);
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
            Message::Search(query) => {
                self.query = query;
                self.ui.item_page = 0;
            }
            Message::Navigate(destination) if self.connection.session.is_some() => {
                if matches!(destination, Navigate::New) && !self.writes_allowed() {
                    return Task::none();
                }
                self.tab = Tab::Vault;
                return self.navigate(destination);
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
            Message::UndoDelete if self.writes_allowed() && self.editor.is_none() => {
                if let Some((id, session)) = self.ui.undo_trash.take()
                    && self.connection.session.as_ref() == Some(&session)
                {
                    return self.request(
                        Job::Workflow(workflows::Action::RestoreTrash(id)),
                        ServerCommand::RestoreTrash(id),
                        None,
                    );
                }
            }
            Message::CopyUsername
                if self.writes_allowed()
                    && self.connection.session.is_some()
                    && self.editor.is_none() =>
            {
                return self.launch(Job::UsernameDefaults, backend::reload_settings);
            }
            Message::OpenWebsite(index)
                if self.connection.session.is_some() && self.editor.is_none() =>
            {
                if let Some(url) = self
                    .item
                    .as_ref()
                    .and_then(|item| item.urls.get(index))
                    .cloned()
                {
                    return self.launch(Job::OpenWebsite, move || {
                        website::open(&url).map_err(Failure::from)?;
                        Ok(Reply::WebsiteOpened)
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
                return self.launch(Job::SaveEditorDefaults, backend::reload_settings);
            }
            Message::Save if self.writes_allowed() && self.tab == Tab::Settings => {
                return self.update(Message::SaveSettings);
            }
            Message::Save
                if self.writes_allowed() && self.tab == Tab::Vault && self.editor.is_some() =>
            {
                self.workspace.prepared = None;
                return self.launch(Job::SaveDefaults, backend::reload_settings);
            }
            Message::RevealField(target) => match self.custom_field_command(target, false) {
                Ok((command, revision)) => {
                    self.hide_secrets();
                    return self.request(Job::Field(target), command, Some(revision));
                }
                Err(error) => self.report_error(error),
            },
            Message::HideField(target) => {
                if let Some(field) = self
                    .item
                    .as_mut()
                    .filter(|item| item.id == target.id && item.revision == target.revision)
                    .and_then(|item| item.fields.get_mut(target.index))
                    && field.secret
                {
                    field.value = None;
                }
                if self.item.as_ref().is_some_and(|item| {
                    item.password.is_none()
                        && item
                            .fields
                            .iter()
                            .all(|field| !field.secret || field.value.is_none())
                }) {
                    self.reveal_until = None;
                }
            }
            Message::CopyField(target) if self.writes_allowed() => {
                return self.launch(Job::FieldCopyDefaults(target), backend::reload_settings);
            }
            Message::Reveal => {
                if self.reveal_until.is_some() {
                    self.hide_secrets();
                } else if let Some(item) = &self.item {
                    return self.request(
                        Job::Reveal,
                        ServerCommand::ManagementItem {
                            id: item.id,
                            reveal: true,
                        },
                        Some(item.revision),
                    );
                }
            }
            Message::Copy if self.writes_allowed() => {
                return self.launch(Job::ItemCopyDefaults, backend::reload_settings);
            }
            Message::Delete => {
                self.delete_confirm = true;
                return Task::batch([
                    iced::widget::operation::snap_to(
                        "account-details",
                        iced::widget::operation::RelativeOffset::START,
                    ),
                    iced::widget::operation::focus("cancel-delete"),
                ]);
            }
            Message::CancelDelete => self.delete_confirm = false,
            Message::ConfirmDelete if self.writes_allowed() => {
                if let Some(item) = &self.item {
                    return self.request(
                        Job::Delete,
                        ServerCommand::Delete(Target::Id(item.id)),
                        Some(item.revision),
                    );
                }
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
            Message::ReviewConflict if self.editor.conflicted() => {
                if let Some(id) = self.editor.as_ref().and_then(|draft| draft.id) {
                    return self.request(
                        Job::ConflictReview,
                        ServerCommand::ManagementItem { id, reveal: false },
                        None,
                    );
                }
            }
            Message::ReapplyConflict if self.editor.conflicted() => {
                if let Some(original) = &self.item
                    && let Some(latest) = self.editor.reapply(original)
                {
                    self.item = Some(latest);
                    self.notice = "Your edits are reapplied to the reviewed version. Review the draft, then Save item.".into();
                    self.ui.notice_error = false;
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
                        "Settings saved. Restart the server to apply recovery settings. The lock timeout applies on the next unlock."
                    } else { "Settings saved. The lock timeout applies on the next unlock." }.into();
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
                    return match job {
                        Job::GenerateDefaults => self.generate(),
                        Job::SaveDefaults => self.save_item(Job::Save),
                        Job::SaveEditorDefaults => self.save_item(Job::SaveEditor),
                        Job::CopyDefaults => self.copy_generated(),
                        Job::ItemCopyDefaults => self.copy_item(),
                        Job::UsernameDefaults => self.fetch_username(),
                        Job::FieldCopyDefaults(target) => {
                            match self.custom_field_command(target, true) {
                                Ok((command, revision)) => {
                                    self.request(Job::FieldCopy, command, Some(revision))
                                }
                                Err(error) => {
                                    self.report_error(error);
                                    Task::none()
                                }
                            }
                        }
                        Job::WorkflowDefaults(action) => {
                            self.workflow(workflows::Event::Run(action))
                        }
                        Job::WatchOtpDefaults => self
                            .workflow(workflows::Event::Toggle(workflows::Toggle::WatchOtp, true)),
                        Job::WatchCopyDefaults => self.copy_watched_otp(),
                        _ => Task::none(),
                    };
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
                    self.notice.push_str(" Your unsaved edits are kept. Review the latest item before reapplying them.");
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
            (Job::UsernameValue, ResponsePayload::Item(item)) => {
                if self.item.as_ref().is_some_and(|current| {
                    current.id == item.id && current.revision == item.revision
                }) && let Some(username) = item.username.filter(|value| !value.is_empty())
                {
                    let timeout = self.conf.clipboard.timeout;
                    let username = SecretString::from(username);
                    return self.launch(Job::UsernameCopied, move || {
                        password_manager::clipboard::copy_with_timeout(username.expose(), timeout)
                            .map_err(Failure::from)?;
                        Ok(Reply::Copied)
                    });
                }
            }
            (Job::ConflictReview, ResponsePayload::Item(mut item)) => {
                if self.editor.as_ref().and_then(|draft| draft.id) == Some(item.id) {
                    item.password = None;
                    for field in &mut item.fields {
                        if field.secret {
                            field.value = None;
                        }
                    }
                    self.editor.review(item);
                }
            }
            (Job::List, ResponsePayload::ItemPage(page)) => self.replace_items(page.items),
            (Job::SavedList, ResponsePayload::ItemPage(page)) => {
                let selected = self.ui.saved_item.take().and_then(|saved| {
                    let mut matches = page.items.iter().filter(|item| {
                        !saved.previous_ids.contains(&item.id)
                            && item.name == saved.name
                            && item.kind == saved.kind
                    });
                    let id = matches.next()?.id;
                    matches.next().is_none().then_some(id)
                });
                self.replace_items(page.items);
                if let Some(id) = selected {
                    let item = self.items.iter().find(|item| item.id == id).unwrap();
                    return self.open_item(id, ItemIntent::View, Some(item.revision));
                }
                self.notice = "Item saved. Select it from your items to continue.".into();
            }
            (Job::RefreshItem(id, intent), ResponsePayload::ItemPage(page)) => {
                self.replace_items(page.items);
                if let Some(item) = self.items.iter().find(|item| item.id == id) {
                    return self.open_item(id, intent, Some(item.revision));
                }
                self.workspace.hide_secrets();
                self.notice = "This item is no longer available. Refresh the vault.".into();
            }
            (Job::OpenItem(id, ItemIntent::Edit), ResponsePayload::Item(item)) if item.id == id => {
                self.editor = Editor::new(Draft::from_item(&item));
                self.item = Some(item);
                return iced::widget::operation::snap_to_end("credential-editor");
            }
            (Job::Item | Job::OpenItem(_, ItemIntent::View), ResponsePayload::Item(item)) => {
                if let Job::OpenItem(id, ItemIntent::View) = job
                    && item.id != id
                {
                    self.workspace.hide_secrets();
                    self.notice =
                        "The server returned a different account. Refresh the vault.".into();
                    return Task::none();
                }
                self.workspace.selected = Some(workflows::Choice {
                    id: item.id,
                    label: format!("{} · {}", item.id, item.name),
                });
                self.item = Some(item);
                return self.fetch_selected_duo();
            }
            (Job::Field(target), ResponsePayload::Secret(value)) => {
                if let Some(field) = self
                    .item
                    .as_mut()
                    .filter(|item| item.id == target.id && item.revision == target.revision)
                    .and_then(|item| item.fields.get_mut(target.index))
                    && field.secret
                {
                    field.value = Some(value);
                    self.reveal_until = Some(Instant::now() + Duration::from_secs(15));
                    self.notice.clear();
                }
            }
            (Job::FieldCopy, ResponsePayload::Message(message)) => self.notice = message,
            (Job::Reveal, ResponsePayload::Item(item)) => {
                self.item = Some(item);
                self.reveal_until = Some(Instant::now() + Duration::from_secs(15));
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
                        self.notice = "The previous outcome or storage durability is uncertain. Inspect the vault before acknowledging it; the operation will not be retried.".into();
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
            (Job::SaveEditor, _) => {
                if let Some(id) = self.editor.as_ref().and_then(|draft| draft.id) {
                    self.notice = "Item saved. You can configure its authenticators below.".into();
                    return self.refresh_item(id, ItemIntent::Edit, incremental);
                }
            }
            (Job::Save, _) => {
                self.ui.editor_show_secret = false;
                let id = self.editor.as_ref().and_then(|draft| draft.id);
                self.ui.saved_item = self.editor.as_ref().filter(|_| id.is_none()).map(|draft| {
                    presentation::SavedItem {
                        name: draft.name.clone(),
                        kind: draft.kind,
                        previous_ids: self.items.iter().map(|item| item.id).collect(),
                    }
                });
                self.workspace.prepared = None;
                self.workspace.clear_inputs();
                self.editor = Editor::Closed;
                self.item = None;
                self.delete_confirm = false;
                self.notice = "Item saved.".into();
                if incremental {
                    self.ui.saved_item = None;
                }
                if let Some(id) = id.or(incremental.then_some(changed_id).flatten()) {
                    return self.refresh_item(id, ItemIntent::View, incremental);
                }
                return self.load_items_for(Job::SavedList);
            }
            (Job::Delete, _) => {
                if let (Some(item), Some(session)) = (&self.item, &self.connection.session) {
                    self.ui.undo_trash = Some((item.id, session.clone()));
                }
                self.workspace.prepared = None;
                self.workspace.clear_inputs();
                self.editor = Editor::Closed;
                self.item = None;
                self.delete_confirm = false;
                self.notice =
                    "Item moved to encrypted trash. You can restore it from Tools → Deleted items."
                        .into();
                return if incremental {
                    Task::none()
                } else {
                    self.load_items()
                };
            }
            (Job::Copy, _) => self.notice = "Secret copied with timed clipboard cleanup.".into(),
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
