//! An Iced client of the existing server, never a second owner of vault state.
mod backend;
mod file_picker;
mod model;
mod settings;
mod view;

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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Job {
    Connect,
    Status,
    List,
    Item,
    Reveal,
    Unlock,
    Lock,
    Create,
    Save,
    Delete,
    Copy,
    Stop,
    Reconcile,
    Acknowledge,
    Settings,
    CopyGenerated,
    PickKey,
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
    Tab(Tab),
    Search(String),
    Navigate(Navigate),
    Discard,
    KeepEditing,
    Vault(String),
    Master(SecretString),
    ConfirmMaster(SecretString),
    KeyPath(SecretString),
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
    Url(usize, String),
    AddUrl,
    RemoveUrl(usize),
    Notes(text_editor::Action),
    Save,
    Reveal,
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
    tab: Tab,
    running: bool,
    session: Option<String>,
    vaults: Vec<String>,
    vault: Option<String>,
    master: SecretString,
    confirmation: SecretString,
    key_path: SecretString,
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
}

impl App {
    fn new(conf: Config, client: AuthenticatedClient) -> Self {
        Self {
            generator_length: conf.genpass.length.to_string(),
            settings: SettingsDraft::from(&conf),
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
        }
    }

    fn boot(conf: Config, client: AuthenticatedClient) -> (Self, Task<Message>) {
        let mut app = Self::new(conf, client);
        let task = app.connect();
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
        self.revealing = job == Job::Reveal;
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
        self.request(
            Job::List,
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

    fn hide_secrets(&mut self) {
        if self.revealing {
            // Focus loss/Escape can arrive before a reveal request completes.
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
    }

    fn navigate(&mut self, destination: Navigate) -> Task<Message> {
        if self.draft.as_ref().is_some_and(|draft| draft.dirty) {
            self.deferred = Some(destination);
            return Task::none();
        }
        self.hide_secrets();
        self.delete_confirm = false;
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
                        if let Some(id) = error.uncertain_operation {
                            self.pending = Some(id);
                            self.reviewed = false;
                            self.notice.push_str(" The change may have completed. Check its outcome before making another change.");
                            self.draft = None;
                            self.hide_secrets();
                        }
                        if matches!(job, Job::Connect | Job::Status) {
                            self.running = false;
                            self.clear_vault();
                        }
                        Task::none()
                    }
                };
            }
            Message::Tick(now) => {
                if self.reveal_until.is_some_and(|deadline| now >= deadline) {
                    self.hide_secrets();
                }
                if self.generated_until.is_some_and(|deadline| now >= deadline) {
                    self.generated.zeroize();
                    self.generated_stats.clear();
                    self.generated_until = None;
                    self.show_generated = false;
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
            Message::Connect => return self.connect(),
            Message::Tab(tab) => {
                self.hide_secrets();
                self.tab = tab;
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
                let key = if !self.key_path.is_empty() {
                    if !std::path::Path::new(self.key_path.expose()).is_absolute() {
                        self.notice = "Enter an absolute key-file path.".into();
                        return Task::none();
                    }
                    PasswordType::Key(std::mem::take(&mut self.key_path).expose_owned())
                } else {
                    PasswordType::Password(std::mem::take(&mut self.master).expose_owned())
                };
                self.master.zeroize();
                self.key_path.zeroize();
                return self.request(
                    Job::Unlock,
                    ServerCommand::Unlock(UnlockInfo {
                        key,
                        timeout: self.conf.unlock.timeout,
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
                    self.hide_secrets();
                }
            }
            Message::Name(value) => {
                if let Some(draft) = &mut self.draft {
                    draft.name = value;
                    draft.dirty = true;
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
            Message::ReplacePassword(value) => {
                if let Some(draft) = &mut self.draft {
                    draft.replace_password = value;
                    if !value {
                        draft.password.zeroize();
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
            Message::Save if self.writes_allowed() => {
                if let Some(draft) = &self.draft {
                    match draft.command() {
                        Ok(mut command) => {
                            if let ServerCommand::Add {
                                entry,
                                copy_timeout,
                            } = &mut command
                            {
                                entry.entry.copy = self.conf.copy.passwords
                                    && self.conf.clipboard.timeout > 0
                                    && entry.kind == ItemKind::Login;
                                *copy_timeout = self.conf.clipboard.timeout;
                            }
                            return self.request(Job::Save, command, draft.revision);
                        }
                        Err(error) => self.notice = error,
                    }
                }
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
                let generated = if self.passphrase {
                    self.words
                        .parse::<u8>()
                        .ok()
                        .filter(|words| (1..=32).contains(words))
                        .ok_or_else(|| "Choose between 1 and 32 words.".into())
                        .and_then(|words| {
                            password_manager::password::generate_passphrase(words, "-")
                        })
                } else {
                    self.generator_length
                        .parse::<u8>()
                        .ok()
                        .filter(|length| *length > 0)
                        .ok_or_else(|| "Choose a length between 1 and 255.".into())
                        .and_then(|length| {
                            password_manager::password::generate_password_with_options(
                                length,
                                &password_manager::password::PasswordOptions {
                                    exclude_ambiguous: true,
                                    ..Default::default()
                                },
                            )
                        })
                };
                match generated {
                    Ok(value) => {
                        if self.tab == Tab::Vault
                            && let Some(draft) = &mut self.draft
                        {
                            draft.password = value.into();
                            draft.replace_password = true;
                            draft.dirty = true;
                            self.notice =
                                "Generated a replacement password. Save the item to keep it."
                                    .into();
                        } else {
                            self.generated = value.into();
                            self.generated_stats = if self.conf.genpass.stats {
                                password_manager::password::password_strength_output(
                                    self.generated.expose(),
                                )
                            } else {
                                String::new()
                            };
                            self.generated_until = Some(Instant::now() + Duration::from_secs(60));
                            self.show_generated = false;
                            if self.conf.genpass.copy && self.conf.clipboard.timeout > 0 {
                                return self.copy_generated();
                            }
                        }
                    }
                    Err(error) => self.notice = error,
                }
            }
            Message::ShowGenerated(value) => self.show_generated = value,
            Message::CopyGenerated if !self.generated.is_empty() => {
                return self.copy_generated();
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
                    if conf.server.port != self.conf.server.port
                        && self.client.port == self.conf.server.port
                    {
                        self.client.port = conf.server.port;
                        self.clear_vault();
                        self.running = false;
                    }
                    if conf.unlock.vault_id != self.conf.unlock.vault_id {
                        self.vault = conf.unlock.vault_id.clone();
                    }
                    self.settings = SettingsDraft::from(&conf);
                    self.generator_length = conf.genpass.length.to_string();
                    self.generated_stats = if conf.genpass.stats && !self.generated.is_empty() {
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
        if response.code != ResponseCode::Success as i32 {
            self.notice = response.error_message();
            self.hide_secrets();
            if response.code == ResponseCode::Conflict as i32 {
                self.draft = None;
                self.item = None;
                self.notice
                    .push_str(" Refresh and reopen the item before making changes.");
            }
            if matches!(job, Job::Connect | Job::Status) {
                self.running = false;
                self.clear_vault();
                return Task::none();
            }
            return self.status();
        }
        if matches!(job, Job::Connect | Job::Status) {
            if let ResponsePayload::Status(status) = response.payload {
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
                    if job == Job::Connect {
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
        ) && self.session != response.session_id
        {
            self.clear_vault();
            self.notice =
                "The vault session changed. Unlock or reopen the vault to continue.".into();
            return self.status();
        }
        match (job, response.payload) {
            (Job::List, ResponsePayload::ItemPage(page)) => self.items = page.items,
            (Job::Item, ResponsePayload::Item(item)) => self.item = Some(item),
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
            (Job::Save | Job::Delete, _) => {
                self.draft = None;
                self.item = None;
                self.delete_confirm = false;
                self.notice = if job == Job::Save {
                    "Item saved."
                } else {
                    "Item moved to trash. Restore it with pm restore."
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

    fn copy_generated(&mut self) -> Task<Message> {
        let value = self.generated.clone();
        let timeout = self.conf.clipboard.timeout;
        if value.is_empty() || timeout == 0 {
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
