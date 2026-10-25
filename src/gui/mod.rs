//! An Iced client of the existing server, never a second owner of vault state.
mod backend;
mod connection;
mod file_picker;
mod generator;
mod model;
mod settings;
mod view;
mod workflows;

use backend::{Failure, Reply};
use iced::{Element, Subscription, Task, Theme, keyboard, widget::text_editor};
use model::Draft;
use password_manager::{
    client::AuthenticatedClient,
    config::{Config, ConfigChanges},
    protocol::{OperationState, RequestEnvelope, ResponseCode, ResponsePayload},
    secret::SecretString,
    types::{
        ItemKind, ListOptions, PasswordType, SearchFilter, ServerCommand, SortField, Target,
        UnlockInfo,
    },
    vault::{ItemDetail, ItemSummary},
};
use settings::{Field as SettingsField, SettingsDraft, Toggle as SettingsToggle};
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
    .theme(Theme::TokyoNight)
    .window(iced::window::Settings {
        size: iced::Size::new(1060.0, 760.0),
        min_size: Some(iced::Size::new(780.0, 580.0)),
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
    GenerateDefaults,
    SaveDefaults,
    SaveEditorDefaults,
    CopyDefaults,
    ItemCopyDefaults,
    FieldCopyDefaults(FieldTarget),
    WorkflowDefaults(workflows::Action),
    WatchOtpDefaults,
    WatchCopyDefaults,
    Status,
    List,
    Item,
    EditorList(usize),
    EditorItem(usize),
    AccountList(usize),
    AccountItem(usize),
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
    PickKey,
    PickFile(workflows::Field),
    Workflow(workflows::Action),
    Local,
}

#[derive(Clone, Debug)]
enum Navigate {
    Select(usize),
    New,
    Close,
    Refresh,
}

#[derive(Clone)]
enum Message {
    Tick(Instant),
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
    ReplacePassword(bool),
    CopyPolicy(model::ClipboardPolicy),
    AddField,
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
    Reconcile,
    Acknowledge,
    GeneratorLength(String),
    Passphrase(bool),
    Words(String),
    Generate,
    CopyGenerated,
    ShowGenerated(bool),
    SettingChanged(SettingsField, String),
    SettingToggled(SettingsToggle, bool),
    SaveSettings,
    ResetSettings,
    CancelResetSettings,
    ConfirmResetSettings,
    FocusNext(bool),
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

struct App {
    conf: Config,
    client: AuthenticatedClient,
    connection_port: String,
    connect_after_discovery: bool,
    tab: Tab,
    running: bool,
    session: Option<String>,
    vaults: Vec<String>,
    vault: Option<String>,
    master: SecretString,
    confirmation: SecretString,
    key_path: SecretString,
    unlock_timeout: String,
    creating: bool,
    select_created_vault: bool,
    items: Vec<ItemSummary>,
    query: String,
    item: Option<ItemDetail>,
    draft: Option<Draft>,
    deferred: Option<Navigate>,
    delete_confirm: bool,
    reveal_until: Option<Instant>,
    busy: bool,
    polling: bool,
    revealing: bool,
    serial: u64,
    last_status: Instant,
    notice: String,
    warning: Option<String>,
    pending: Option<String>,
    reviewed: bool,
    generator_length: String,
    passphrase: bool,
    words: String,
    generated: SecretString,
    generated_until: Option<Instant>,
    show_generated: bool,
    generated_stats: String,
    settings: SettingsDraft,
    confirm_reset_settings: bool,
    workspace: workflows::State,
    generator: generator::Options,
}

impl App {
    fn new(conf: Config, client: AuthenticatedClient) -> Self {
        Self {
            connection_port: client.port.to_string(),
            connect_after_discovery: false,
            generator_length: conf.genpass.length.to_string(),
            settings: SettingsDraft::from(&conf),
            unlock_timeout: conf.unlock.timeout.to_string(),
            vault: conf.unlock.vault_id.clone(),
            conf,
            client,
            tab: Tab::Vault,
            running: false,
            session: None,
            vaults: vec![],
            master: SecretString::default(),
            confirmation: SecretString::default(),
            key_path: SecretString::default(),
            creating: false,
            select_created_vault: false,
            items: vec![],
            query: String::new(),
            item: None,
            draft: None,
            deferred: None,
            delete_confirm: false,
            reveal_until: None,
            busy: false,
            polling: false,
            revealing: false,
            serial: 0,
            last_status: Instant::now(),
            notice: "Connecting to the vault server…".into(),
            warning: None,
            pending: None,
            reviewed: false,
            passphrase: false,
            words: "6".into(),
            generated: SecretString::default(),
            generated_until: None,
            show_generated: false,
            generated_stats: String::new(),
            confirm_reset_settings: false,
            workspace: workflows::State::default(),
            generator: generator::Options::default(),
        }
    }

    fn boot(conf: Config, client: AuthenticatedClient) -> (Self, Task<Message>) {
        let mut app = Self::new(conf, client);
        app.connect_after_discovery = true;
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
                        _ => None,
                    }
                }
                _ => None,
            }),
            iced::event::listen_with(|event, _, _| {
                matches!(event, iced::Event::Window(iced::window::Event::Unfocused))
                    .then_some(Message::HideSecrets)
            }),
        ])
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
        self.polling = job == Job::Status;
        self.revealing = matches!(
            job,
            Job::Reveal
                | Job::Field(_)
                | Job::WatchOtpDefaults
                | Job::WorkflowDefaults(workflows::Action::ShowOtp(true))
        );
        self.busy = !self.polling;
        Task::perform(
            async move {
                tokio::task::spawn_blocking(work).await.unwrap_or_else(|_| Err(Failure::from("The desktop operation could not finish. Inspect the vault before retrying any change.".to_owned())))
            },
            move |result| Message::Finished(serial, job, Arc::new(result)),
        )
    }

    fn connect(&mut self) -> Task<Message> {
        let client = self.client.clone();
        self.last_status = Instant::now();
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
            envelope.expected_session = self.session.clone();
        }
        envelope.expected_revision = revision;
        let client = self.client.clone();
        self.launch(job, move || backend::request(&client, envelope))
    }

    fn status(&mut self) -> Task<Message> {
        self.last_status = Instant::now();
        self.request(Job::Status, ServerCommand::Status, None)
    }

    fn load_items(&mut self) -> Task<Message> {
        self.load_items_for(Job::List)
    }

    fn load_items_for(&mut self, job: Job) -> Task<Message> {
        self.request(
            job,
            ServerCommand::ManagementList(SearchFilter {
                list: ListOptions {
                    sort: SortField::Name,
                    ..Default::default()
                },
                ..Default::default()
            }),
            None,
        )
    }

    fn refresh_account(&mut self, id: usize) -> Task<Message> {
        self.item = None;
        self.load_items_for(Job::AccountList(id))
    }

    fn refresh_editor(&mut self, id: usize) -> Task<Message> {
        self.hide_secrets();
        self.item = None;
        self.draft = None;
        self.workspace.prepared = None;
        self.workspace.clear_inputs();
        self.load_items_for(Job::EditorList(id))
    }

    fn hide_secrets(&mut self) {
        self.workspace.hide_secrets();
        if let Some(draft) = &mut self.draft {
            // Multiline input is deliberately visible while editing. Focus
            // loss and Escape must mask it just like a revealed stored secret.
            draft.multiline = false;
            draft.secret_editor = text_editor::Content::new();
        }
        if self.revealing {
            // Focus loss/Escape can arrive before a reveal or OTP settings
            // preflight completes. Neither may dispatch new secret work later.
            self.serial += 1;
            self.revealing = false;
            self.busy = false;
        }
        self.reveal_until = None;
        self.show_generated = false;
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
        self.hide_secrets();
        self.session = None;
        self.workspace.clear_vault();
        self.items.clear();
        self.query.zeroize();
        self.item = None;
        self.draft = None;
        self.deferred = None;
        self.delete_confirm = false;
        self.master.zeroize();
        self.confirmation.zeroize();
        self.key_path.zeroize();
        self.generated.zeroize();
        self.generated_stats.clear();
        self.generated_until = None;
        self.generator.check.zeroize();
        self.generator.assessment.clear();
    }

    fn cancel_passive_read(&mut self) {
        if self.polling {
            self.serial += 1;
            self.polling = false;
        }
    }

    fn navigate(&mut self, destination: Navigate) -> Task<Message> {
        if self.draft.as_ref().is_some_and(|draft| draft.dirty) {
            self.deferred = Some(destination);
            return Task::none();
        }
        self.hide_secrets();
        self.cancel_passive_read();
        self.delete_confirm = false;
        self.workspace.prepared = None;
        self.workspace.clear_inputs();
        self.draft = None;
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
                self.draft = Some(Draft::default());
                Task::none()
            }
            Navigate::Close => Task::none(),
            Navigate::Refresh => self.load_items(),
        }
    }

    fn writes_allowed(&self) -> bool {
        !self.busy && self.pending.is_none()
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
                | Message::FieldSecret(..)
                | Message::RemoveField(_)
                | Message::MultilineSecret(_)
                | Message::SecretEdit(_)
                | Message::Url(..)
                | Message::AddUrl
                | Message::RemoveUrl(_)
                | Message::Notes(_)
                | Message::Generate
        ) && self.draft.is_some()
            && !self.busy
        {
            self.workspace.prepared = None;
        }
        match message {
            Message::Finished(serial, job, result) => {
                if serial != self.serial {
                    return Task::none();
                }
                self.busy = false;
                self.polling = false;
                self.revealing = false;
                let result = Arc::try_unwrap(result).unwrap_or_else(|shared| (*shared).clone());
                return match result {
                    Ok(reply) => self.complete(job, reply),
                    Err(error) => {
                        self.notice = error.message;
                        if matches!(job, Job::Workflow(_)) {
                            self.stop_tool_watches();
                        }
                        if let Some(id) = error.uncertain_operation {
                            self.pending = Some(id);
                            self.reviewed = false;
                            self.notice.push_str(" The change may have completed. Check its outcome before making another change.");
                            self.draft = None;
                            self.hide_secrets();
                        }
                        if matches!(job, Job::Connect | Job::Attach | Job::Status) {
                            self.running = false;
                            self.clear_vault();
                        }
                        if job == Job::DiscoverVaults && self.connect_after_discovery {
                            self.connect_after_discovery = false;
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
                if self.generated_until.is_some_and(|deadline| now >= deadline) {
                    self.generated.zeroize();
                    self.generated_stats.clear();
                    self.generated_until = None;
                    self.show_generated = false;
                }
                if !self.busy
                    && !self.polling
                    && now.saturating_duration_since(self.last_status) < Duration::from_secs(2)
                {
                    let task = self.poll_tool_watches(now);
                    if self.polling || self.busy {
                        return task;
                    }
                }
                if self.running
                    && !self.busy
                    && !self.polling
                    && now.duration_since(self.last_status) >= Duration::from_secs(2)
                {
                    return self.status();
                }
            }
            Message::Lock if self.running => {
                // Invalidate older completions immediately, even if a request is in flight.
                self.clear_vault();
                self.notice.clear();
                return self.request(Job::Lock, ServerCommand::Lock(true), None);
            }
            Message::HideSecrets => self.hide_secrets(),
            Message::FocusNext(backwards) => {
                return if backwards {
                    iced::widget::operation::focus_previous()
                } else {
                    iced::widget::operation::focus_next()
                };
            }
            _ if self.busy => return Task::none(),
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
            Message::Generator(event) => self.generator.update(event),
            Message::OpenToolItem(id) => {
                self.tab = Tab::Vault;
                return self.navigate(Navigate::Select(id));
            }
            Message::OpenItemTools(id) => {
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
            Message::Connect => return self.connect(),
            Message::RefreshVaults => return self.refresh_vaults(),
            Message::ReloadSettings => return self.reload_settings(),
            Message::ConnectionPort(value) => self.connection_port = value,
            Message::UseConnectionPort => return self.use_connection_port(),
            Message::Tab(tab) => {
                self.hide_secrets();
                self.cancel_passive_read();
                self.workspace.prepared = None;
                self.tab = tab;
                if tab == Tab::Vault && self.draft.is_none() {
                    if let Some(item) = &self.item {
                        self.workspace.selected = Some(workflows::Choice {
                            id: item.id,
                            label: format!("{} · {}", item.id, item.name),
                        });
                    }
                    return self.fetch_selected_duo();
                }
                if tab == Tab::Settings {
                    return self.reload_settings();
                }
            }
            Message::Search(query) => self.query = query,
            Message::Navigate(destination) if self.session.is_some() => {
                return self.navigate(destination);
            }
            Message::Discard => {
                self.draft = None;
                if let Some(destination) = self.deferred.take() {
                    return self.navigate(destination);
                }
            }
            Message::KeepEditing => self.deferred = None,
            Message::Vault(vault) => {
                self.master.zeroize();
                self.key_path.zeroize();
                self.vault = Some(vault);
            }
            Message::Master(password) => self.master = password,
            Message::ConfirmMaster(password) => self.confirmation = password,
            Message::KeyPath(path) => self.key_path = path,
            Message::UnlockTimeout(value) => self.unlock_timeout = value,
            Message::BrowseKey if !self.creating && self.session.is_none() => {
                self.serial += 1;
                self.busy = true;
                self.polling = false;
                return file_picker::pick_key_file(self.serial);
            }
            Message::Creating(creating) => {
                self.creating = creating;
                self.master.zeroize();
                self.confirmation.zeroize();
                self.key_path.zeroize();
            }
            Message::Unlock => {
                let timeout = match password_manager::config::parse_duration(&self.unlock_timeout) {
                    Ok(timeout) => timeout,
                    Err(error) => {
                        self.notice = format!("Lock timeout: {error}");
                        return Task::none();
                    }
                };
                let key = if !self.key_path.is_empty() {
                    let path = match workflows::absolute(self.key_path.expose()) {
                        Ok(path) => path,
                        Err(error) => {
                            self.notice = error;
                            return Task::none();
                        }
                    };
                    PasswordType::Key(path)
                } else {
                    PasswordType::Password(std::mem::take(&mut self.master).expose_owned())
                };
                self.master.zeroize();
                self.key_path.zeroize();
                return self.request(
                    Job::Unlock,
                    ServerCommand::Unlock(UnlockInfo {
                        key,
                        timeout,
                        vault_file: self.vault.clone(),
                    }),
                    None,
                );
            }
            Message::Create if self.writes_allowed() => {
                if self.master != self.confirmation {
                    self.notice = "The two master passwords do not match.".into();
                    return Task::none();
                }
                // The server applies the same password policy as the CLI.
                let key = PasswordType::Password(std::mem::take(&mut self.master).expose_owned());
                self.confirmation.zeroize();
                return self.request(Job::Create, ServerCommand::New(key), None);
            }
            Message::Stop if self.pending.is_none() => {
                self.clear_vault();
                return self.request(Job::Stop, ServerCommand::Kill, None);
            }
            Message::Edit => {
                if let Some(item) = &self.item {
                    self.draft = Some(Draft::from_item(item));
                    self.workspace.prepared = None;
                    self.workspace.clear_inputs();
                    self.hide_secrets();
                }
            }
            Message::Name(value) => {
                if let Some(draft) = &mut self.draft {
                    draft.name = value;
                    draft.dirty = true;
                }
            }
            Message::AddField => {
                if let Some(draft) = &mut self.draft {
                    draft.fields.push(model::FieldDraft::default());
                    draft.dirty = true;
                }
            }
            Message::FieldName(index, value) => {
                if let Some(draft) = &mut self.draft
                    && let Some(field) = draft.fields.get_mut(index)
                {
                    field.name = value;
                    field.changed = true;
                    draft.dirty = true;
                }
            }
            Message::FieldValue(index, value) => {
                if let Some(draft) = &mut self.draft
                    && let Some(field) = draft.fields.get_mut(index)
                {
                    field.value = value;
                    field.changed = true;
                    field.value_edited = true;
                    draft.dirty = true;
                }
            }
            Message::FieldSecret(index, value) => {
                if let Some(draft) = &mut self.draft
                    && let Some(field) = draft.fields.get_mut(index)
                {
                    field.secret = value;
                    field.changed = true;
                    draft.dirty = true;
                }
            }
            Message::RemoveField(index) => {
                if let Some(draft) = &mut self.draft
                    && let Some(field) = draft.fields.get_mut(index)
                {
                    field.removed = true;
                    field.value.zeroize();
                    draft.dirty = true;
                }
            }
            Message::MultilineSecret(value) => {
                if let Some(draft) = &mut self.draft {
                    draft.multiline = value;
                    draft.secret_editor = if value {
                        text_editor::Content::with_text(draft.password.expose())
                    } else {
                        text_editor::Content::new()
                    };
                }
            }
            Message::SecretEdit(action) => {
                if let Some(draft) = &mut self.draft
                    && draft.multiline
                    && (draft.id.is_none() || draft.replace_password)
                {
                    let editing = action.is_edit();
                    draft.secret_editor.perform(action);
                    if editing {
                        draft.password = draft.secret_editor.text().into();
                        draft.dirty = true;
                    }
                }
            }
            Message::Username(value) => {
                if let Some(draft) = &mut self.draft {
                    draft.username = value;
                    draft.dirty = true;
                }
            }
            Message::Kind(value) => {
                if let Some(draft) = &mut self.draft {
                    draft.kind = value;
                    draft.dirty = true;
                }
            }
            Message::Password(value) => {
                if let Some(draft) = &mut self.draft {
                    draft.password = value;
                    draft.replace_password = true;
                    draft.dirty = true;
                }
            }
            Message::CopyPolicy(policy) => {
                if let Some(draft) = &mut self.draft {
                    draft.copy_policy = policy;
                }
            }
            Message::ReplacePassword(value) => {
                if let Some(draft) = &mut self.draft {
                    draft.replace_password = value;
                    if !value {
                        draft.password.zeroize();
                        draft.secret_editor = text_editor::Content::new();
                    }
                    draft.dirty = true;
                }
            }
            Message::Url(index, value) => {
                if let Some(draft) = &mut self.draft
                    && let Some(url) = draft.urls.get_mut(index)
                {
                    *url = value;
                    draft.dirty = true;
                }
            }
            Message::AddUrl => {
                if let Some(draft) = &mut self.draft {
                    draft.urls.push(String::new());
                    draft.dirty = true;
                }
            }
            Message::RemoveUrl(index) => {
                if let Some(draft) = &mut self.draft
                    && index < draft.urls.len()
                {
                    draft.urls.remove(index);
                    draft.dirty = true;
                }
            }
            Message::Notes(action) => {
                if let Some(draft) = &mut self.draft {
                    if action.is_edit() {
                        draft.notes_changed = true;
                        draft.dirty = true;
                    }
                    draft.notes.perform(action);
                }
            }
            Message::SaveAndEdit
                if self.writes_allowed()
                    && self.draft.as_ref().is_some_and(|draft| draft.id.is_some()) =>
            {
                self.workspace.prepared = None;
                return self.launch(Job::SaveEditorDefaults, backend::reload_settings);
            }
            Message::Save if self.writes_allowed() => {
                self.workspace.prepared = None;
                return self.launch(Job::SaveDefaults, backend::reload_settings);
            }
            Message::RevealField(target) => match self.custom_field_command(target, false) {
                Ok((command, revision)) => {
                    self.hide_secrets();
                    return self.request(Job::Field(target), command, Some(revision));
                }
                Err(error) => self.notice = error,
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
            Message::Delete => self.delete_confirm = true,
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
                if let Some(id) = &self.pending {
                    return self.request(
                        Job::Reconcile,
                        ServerCommand::OperationStatus(id.clone()),
                        None,
                    );
                }
            }
            Message::Acknowledge if self.reviewed => {
                if let Some(id) = self.pending.clone() {
                    let client = self.client.clone();
                    return self
                        .launch(Job::Acknowledge, move || backend::acknowledge(&client, &id));
                }
            }
            Message::GeneratorLength(value) => self.generator_length = value,
            Message::Passphrase(value) => self.passphrase = value,
            Message::Words(value) => self.words = value,
            Message::Generate => {
                return self.launch(Job::GenerateDefaults, backend::reload_settings);
            }
            Message::ShowGenerated(value) => self.show_generated = value,
            Message::CopyGenerated if !self.generated.is_empty() => {
                return self.launch(Job::CopyDefaults, backend::reload_settings);
            }
            Message::SettingChanged(field, value) => {
                self.settings.edit(field, value);
                self.confirm_reset_settings = false;
            }
            Message::SettingToggled(toggle, value) => {
                self.settings.toggle(toggle, value);
                self.confirm_reset_settings = false;
            }
            Message::SaveSettings => match self.settings.changes() {
                Ok(changes) => {
                    return self.launch(Job::Settings, move || backend::save_settings(changes));
                }
                Err(error) => self.notice = error,
            },
            Message::ResetSettings => self.confirm_reset_settings = true,
            Message::CancelResetSettings => self.confirm_reset_settings = false,
            Message::ConfirmResetSettings if self.confirm_reset_settings => {
                self.confirm_reset_settings = false;
                return self.launch(Job::Settings, || {
                    backend::save_settings(ConfigChanges {
                        reset: true,
                        ..Default::default()
                    })
                });
            }
            _ => {}
        }
        Task::none()
    }

    fn complete(&mut self, job: Job, reply: Reply) -> Task<Message> {
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
                    let restart_required =
                        restart_required || self.running && conf.recovery != self.conf.recovery;
                    if !self.running
                        && conf.server.port != self.conf.server.port
                        && self.client.port == self.conf.server.port
                    {
                        self.reset_connection(conf.server.port);
                    }
                    if conf.unlock.vault_id != self.conf.unlock.vault_id {
                        self.vault = conf.unlock.vault_id.clone();
                    }
                    self.settings = SettingsDraft::from(&conf);
                    self.unlock_timeout = conf.unlock.timeout.to_string();
                    self.generator_length = conf.genpass.length.to_string();
                    self.generated_stats =
                        if self.generator.stats_enabled(&conf) && !self.generated.is_empty() {
                            password_manager::password::password_strength_output(
                                self.generated.expose(),
                            )
                        } else {
                            String::new()
                        };
                    self.conf = conf;
                    self.notice = if restart_required {
                        "Settings saved. Restart the server to apply recovery settings. The lock timeout applies on the next unlock."
                    } else { "Settings saved. The lock timeout applies on the next unlock." }.into();
                }
                Reply::Vaults(vaults) => {
                    self.apply_vaults(vaults);
                    if self.connect_after_discovery {
                        self.connect_after_discovery = false;
                        return self.connect();
                    }
                }
                Reply::Configuration(conf) => {
                    self.apply_configuration(conf);
                    return match job {
                        Job::GenerateDefaults => self.generate(),
                        Job::SaveDefaults => self.save_item(Job::Save),
                        Job::SaveEditorDefaults => self.save_item(Job::SaveEditor),
                        Job::CopyDefaults => self.copy_generated(),
                        Job::ItemCopyDefaults => self.copy_item(),
                        Job::FieldCopyDefaults(target) => {
                            match self.custom_field_command(target, true) {
                                Ok((command, revision)) => {
                                    self.request(Job::FieldCopy, command, Some(revision))
                                }
                                Err(error) => {
                                    self.notice = error;
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
                    self.notice = "Generated value copied with timed clipboard cleanup.".into()
                }
                Reply::Acknowledged => {
                    self.pending = None;
                    self.reviewed = false;
                    self.notice =
                        "Previous outcome acknowledged. You can make a new change.".into();
                    return self.status();
                }
                Reply::KeyFile(Some(path)) => {
                    self.key_path = path;
                    self.master.zeroize();
                    self.notice.clear();
                }
                Reply::PickedFile(field, Some(path)) => self.workspace.edit(field, path),
                Reply::Local(message) => self.workspace.receive(ResponsePayload::Message(message)),
                _ => {}
            }
            return Task::none();
        };
        let response = *response;
        if self.pending.is_none() {
            self.pending = pending.first().cloned();
        }
        if let Some(receipt) = &response.operation
            && receipt.state == OperationState::CommittedDurabilityUnknown
        {
            self.pending = Some(receipt.operation_id.clone());
            self.reviewed = false;
        }
        let incomplete_audit = job == Job::Workflow(workflows::Action::Audit)
            && response.code == ResponseCode::Failure as i32
            && matches!(response.payload, ResponsePayload::Audit(_));
        if incomplete_audit && (self.session.is_none() || self.session != response.session_id) {
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
            self.notice = response.error_message();
            self.hide_secrets();
            if response.code == ResponseCode::Conflict as i32 {
                self.stop_tool_watches();
                self.workspace.prepared = None;
                self.draft = None;
                self.item = None;
                self.notice
                    .push_str(" Refresh and reopen the item before making changes.");
            }
            if matches!(job, Job::Connect | Job::Attach | Job::Status) {
                self.running = false;
                self.clear_vault();
                return Task::none();
            }
            return self.status();
        }
        if matches!(job, Job::Connect | Job::Attach | Job::Status) {
            if let ResponsePayload::Status(status) = response.payload {
                if matches!(job, Job::Connect | Job::Attach) {
                    self.notice.clear();
                }
                self.running = true;
                self.warning = status.warning;
                let next_session = if status.locked {
                    None
                } else {
                    response.session_id
                };
                let changed = self.session != next_session;
                if changed {
                    self.clear_vault();
                }
                self.session = next_session;
                if status.locked {
                    if self.select_created_vault {
                        self.vault = vaults
                            .iter()
                            .find(|vault| !self.vaults.contains(vault))
                            .cloned();
                        self.select_created_vault = false;
                    }
                    self.vaults = vaults;
                    if self
                        .vault
                        .as_ref()
                        .is_none_or(|selected| !self.vaults.contains(selected))
                    {
                        self.vault = self.vaults.first().cloned();
                    }
                    if matches!(job, Job::Connect | Job::Attach) {
                        self.notice =
                            "Server connected. Unlock a vault or create one to get started.".into();
                    }
                } else {
                    self.vaults = vaults;
                    if changed {
                        self.creating = false;
                        return self.load_items();
                    }
                }
            }
            return Task::none();
        }
        // A lock or another client switching vaults invalidates every selection.
        if !matches!(
            job,
            Job::Unlock | Job::Lock | Job::Create | Job::Stop | Job::Reconcile
        ) && !matches!(job, Job::Workflow(action) if action.changes_vault())
            && self.session != response.session_id
        {
            self.clear_vault();
            self.notice =
                "The vault session changed. Unlock or reopen the vault to continue.".into();
            return self.status();
        }
        match (job, response.payload) {
            (Job::Workflow(action), payload) => {
                if action == workflows::Action::Requests {
                    return self.complete_duo_requests(payload);
                }
                if matches!(
                    action,
                    workflows::Action::WatchOtp | workflows::Action::CopyWatchedOtp
                ) {
                    return self.complete_otp_watch(action, payload);
                }
                if matches!(action, workflows::Action::Respond(..)) {
                    self.notice = if let ResponsePayload::Message(message) = &payload {
                        message.clone()
                    } else {
                        "Duo response recorded.".into()
                    };
                    self.workspace.duo_requests = None;
                    self.workspace.receive(payload);
                    return self.workflow(workflows::Event::Run(workflows::Action::Requests));
                }
                if matches!(
                    action,
                    workflows::Action::EnrollDuo | workflows::Action::RemoveDuo
                ) {
                    self.workspace.reset_duo();
                }
                let first_result = self.workspace.result.is_none();
                self.notice = if let Some(warning) = audit_warning {
                    format!("Audit completed with incomplete breach checks: {warning}")
                } else if let ResponsePayload::Message(message) = &payload {
                    message.clone()
                } else {
                    if self.tab == Tab::Vault {
                        ""
                    } else {
                        "Results are ready in Tools."
                    }
                    .into()
                };
                if action.changes_vault() {
                    let changes_selection = matches!(
                        action,
                        workflows::Action::NewVault
                            | workflows::Action::RestoreBackup
                            | workflows::Action::DeleteVault
                    ) || action == workflows::Action::Import
                        && self.workspace.import_new;
                    if !changes_selection {
                        if self.session != response.session_id {
                            self.clear_vault();
                            self.session = response.session_id.clone();
                        }
                        self.item = None;
                        self.draft = None;
                        self.workspace.receive(payload);
                        let refresh = if self.session.is_some() {
                            self.load_items()
                        } else {
                            self.status()
                        };
                        return Task::batch([refresh, workflows::show_result()]);
                    }
                    let restored = if let ResponsePayload::Vault(reference) = &payload {
                        Some(reference.vault_file.clone())
                    } else {
                        None
                    };
                    self.clear_vault();
                    if let Some(filename) = restored {
                        self.vault = Some(filename);
                    }
                    if matches!(action, workflows::Action::NewVault)
                        || action == workflows::Action::Import && self.workspace.import_new
                    {
                        self.select_created_vault = true;
                    }
                    self.workspace.receive(payload);
                    return Task::batch([self.status(), workflows::show_result()]);
                }
                let consumed_hotp = matches!(
                    &payload,
                    ResponsePayload::Authenticator(code) if code.counter.is_some()
                );
                let refresh = consumed_hotp
                    || matches!(
                        action,
                        workflows::Action::RestorePassword(_)
                            | workflows::Action::RestoreTrash(_)
                            | workflows::Action::SetOtp
                            | workflows::Action::RemoveOtp
                            | workflows::Action::EnrollDuo
                            | workflows::Action::EnrollPasscodes
                            | workflows::Action::RemoveDuo
                    );
                self.workspace.receive(payload);
                if refresh {
                    if self.tab == Tab::Vault
                        && action.edits_authenticator()
                        && let Some(id) = self.draft.as_ref().and_then(|draft| draft.id)
                    {
                        if self
                            .workspace
                            .duo_watch_target
                            .as_ref()
                            .is_some_and(|target| target.choice.id == id)
                        {
                            self.workspace.reset_duo();
                        }
                        return self.refresh_editor(id);
                    }
                    if consumed_hotp
                        && self.tab == Tab::Vault
                        && self.draft.is_none()
                        && let Some(id) = self.item.as_ref().map(|item| item.id)
                    {
                        if self
                            .workspace
                            .duo_watch_target
                            .as_ref()
                            .is_some_and(|target| target.choice.id == id)
                        {
                            self.workspace.reset_duo();
                        }
                        return self.refresh_account(id);
                    }
                    self.item = None;
                    self.draft = None;
                    return Task::batch([self.load_items(), workflows::show_result()]);
                }
                if matches!(action, workflows::Action::ShowOtp(_)) && self.tab == Tab::Vault {
                    return Task::none();
                }
                if first_result || !(self.workspace.watch_otp || self.workspace.watch_duo) {
                    return workflows::show_result();
                }
            }
            (Job::List, ResponsePayload::ItemPage(page)) => self.items = page.items,
            (Job::EditorList(id), ResponsePayload::ItemPage(page)) => {
                self.items = page.items;
                if let Some(item) = self.items.iter().find(|item| item.id == id) {
                    return self.request(
                        Job::EditorItem(id),
                        ServerCommand::ManagementItem { id, reveal: false },
                        Some(item.revision),
                    );
                }
                self.notice = "This item is no longer available. Refresh the vault.".into();
            }
            (Job::EditorItem(id), ResponsePayload::Item(item)) if item.id == id => {
                self.draft = Some(Draft::from_item(&item));
                self.item = Some(item);
                return iced::widget::operation::snap_to_end("credential-editor");
            }
            (Job::AccountList(id), ResponsePayload::ItemPage(page)) => {
                self.items = page.items;
                if let Some(item) = self.items.iter().find(|item| item.id == id) {
                    return self.request(
                        Job::AccountItem(id),
                        ServerCommand::ManagementItem { id, reveal: false },
                        Some(item.revision),
                    );
                }
                self.workspace.hide_secrets();
                self.notice = "This account is no longer available. Refresh the vault.".into();
            }
            (Job::Item | Job::AccountItem(_), ResponsePayload::Item(item)) => {
                if let Job::AccountItem(id) = job
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
                        self.pending = None;
                        self.reviewed = false;
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
                        self.reviewed = true;
                        self.notice = "The previous outcome or storage durability is uncertain. Inspect the vault before acknowledging it; the operation will not be retried.".into();
                    }
                }
                if self.session.is_some() {
                    return self.navigate(Navigate::Refresh);
                }
                return self.status();
            }
            (Job::Stop, _) => {
                self.clear_vault();
                self.running = false;
                self.notice = "Server stopped.".into();
            }
            (Job::Create | Job::Unlock | Job::Lock, _) => {
                self.clear_vault();
                self.creating = false;
                if job == Job::Create {
                    self.vault = None;
                    self.select_created_vault = true;
                }
                self.notice = if job == Job::Create {
                    "Vault created. Select it and unlock to continue.".into()
                } else {
                    String::new()
                };
                return self.status();
            }
            (Job::SaveEditor, _) => {
                if let Some(id) = self.draft.as_ref().and_then(|draft| draft.id) {
                    self.notice = "Item saved. You can configure its authenticators below.".into();
                    return self.refresh_editor(id);
                }
            }
            (Job::Save | Job::Delete, _) => {
                self.workspace.prepared = None;
                self.workspace.clear_inputs();
                self.draft = None;
                self.item = None;
                self.delete_confirm = false;
                self.notice = if job == Job::Save {
                    "Item saved."
                } else {
                    "Item moved to trash. Restore it in Tools → History, trash & audit."
                }
                .into();
                return self.load_items();
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

    fn custom_field_command(
        &self,
        target: FieldTarget,
        copy: bool,
    ) -> Result<(ServerCommand, u64), String> {
        let item = self
            .item
            .as_ref()
            .filter(|item| item.id == target.id && item.revision == target.revision)
            .ok_or("The selected account changed. Select the field again.")?;
        let field = item
            .fields
            .get(target.index)
            .ok_or("This field is no longer available. Refresh the account.")?;
        if copy && self.conf.clipboard.timeout == 0 {
            return Err("Copying is disabled because the clipboard timeout is zero.".into());
        }
        Ok((
            ServerCommand::GetField {
                target: Target::Id(item.id),
                name: field.name.clone(),
                copy_timeout: copy.then_some(self.conf.clipboard.timeout),
            },
            item.revision,
        ))
    }

    fn copy_item(&mut self) -> Task<Message> {
        if self.conf.clipboard.timeout == 0 {
            self.notice = "Copying is disabled because the clipboard timeout is zero.".into();
            return Task::none();
        }
        if let Some(item) = &self.item {
            return self.request(
                Job::Copy,
                ServerCommand::ManagementCopy {
                    id: item.id,
                    timeout: self.conf.clipboard.timeout,
                },
                Some(item.revision),
            );
        }
        Task::none()
    }

    fn save_item(&mut self, job: Job) -> Task<Message> {
        if let Some(draft) = &self.draft {
            match draft.command() {
                Ok(mut command) => {
                    draft.apply_copy_policy(&mut command, &self.conf);
                    return self.request(job, command, draft.revision);
                }
                Err(error) => self.notice = error,
            }
        }
        Task::none()
    }

    fn generate(&mut self) -> Task<Message> {
        let policy = match self.generator.generation_policy(&self.conf) {
            Ok(policy) => policy,
            Err(error) => {
                self.notice = error;
                return Task::none();
            }
        };
        let generated =
            self.generator
                .generate(self.passphrase, &self.generator_length, &self.words);
        match generated {
            Ok(value) => {
                if self.tab == Tab::Vault
                    && let Some(draft) = &mut self.draft
                {
                    draft.password = value.into();
                    draft.secret_editor = if draft.multiline {
                        text_editor::Content::with_text(draft.password.expose())
                    } else {
                        text_editor::Content::new()
                    };
                    draft.replace_password = true;
                    draft.dirty = true;
                    self.notice =
                        "Generated a replacement password. Save the item to keep it.".into();
                } else {
                    self.generated = value.into();
                    self.generated_stats = if policy.stats {
                        password_manager::password::password_strength_output(
                            self.generated.expose(),
                        )
                    } else {
                        String::new()
                    };
                    self.generated_until = Some(Instant::now() + Duration::from_secs(60));
                    self.show_generated = false;
                    if policy.copy {
                        return self.copy_generated();
                    }
                }
            }
            Err(error) => self.notice = error,
        }
        Task::none()
    }

    fn copy_generated(&mut self) -> Task<Message> {
        let value = self.generated.clone();
        let timeout = match self.generator.copy_timeout(&self.conf) {
            Ok(timeout) => timeout,
            Err(error) => {
                self.notice = error;
                return Task::none();
            }
        };
        if value.is_empty() {
            return Task::none();
        }
        if timeout == 0 {
            self.notice = "Copying is disabled because the clipboard timeout is zero.".into();
            return Task::none();
        }
        self.launch(Job::CopyGenerated, move || {
            password_manager::clipboard::copy_with_timeout(value.expose(), timeout)?;
            Ok(Reply::Copied)
        })
    }
}

#[cfg(test)]
mod tests;
