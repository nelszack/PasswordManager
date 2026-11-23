//! Scripted desktop flows against a real vault server, without a window.
//!
//! Each flow runs in a child copy of this test binary whose home, config and
//! data directories are a fresh temporary folder, so it never touches the
//! user's settings or vaults. The child starts the real server in-process on
//! a free port, boots the real `App`, and drives it: text entry is sent as the
//! input's message, buttons are clicked by their label through the rendered
//! view (so a missing or disabled button fails the flow), and every task the
//! app returns, including its server requests, runs to completion with its
//! results fed back into `update`.
use super::*;
use iced::{
    Rectangle, Size,
    advanced::{layout, mouse, renderer, widget},
    futures::{StreamExt, stream::SelectAll},
};
use std::time::{Duration, Instant};

const SANDBOX_ENV: &str = "PM_GUI_FLOW_SANDBOX";
const WIDTH: f32 = 1060.0;
// Tall enough that every control in a flow is on screen without scrolling;
// layout at real window sizes is covered by the render tests.
const HEIGHT: f32 = 1600.0;
const MASTER: &str = "Synthetic-Flow-Vault-4821!";

/// Run `body` in a child test process with its own home, config and data directories.
fn sandboxed(name: &str, body: impl FnOnce()) {
    if std::env::var_os(SANDBOX_ENV).is_some() {
        body();
        return;
    }
    let root = tempfile::tempdir().unwrap();
    // `main` creates both directories before the desktop app starts.
    for directory in ["pm-config", "pm-data"] {
        std::fs::create_dir_all(root.path().join(directory)).unwrap();
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            &format!("gui::flow_tests::{name}"),
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(SANDBOX_ENV, "1")
        .env("HOME", root.path())
        .env("USERPROFILE", root.path())
        .env("XDG_CONFIG_HOME", root.path().join("config"))
        .env("XDG_DATA_HOME", root.path().join("data"))
        .env("PM_CONFIG_DIR", root.path().join("pm-config"))
        .env("PM_DATA_DIR", root.path().join("pm-data"))
        .output()
        .unwrap();
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success() && report.contains("1 passed"),
        "flow {name} failed:\n{report}"
    );
}

#[derive(Default)]
struct Texts(Vec<(String, Rectangle)>);

impl widget::Operation for Texts {
    fn text(&mut self, _: Option<&widget::Id>, bounds: Rectangle, text: &str) {
        self.0.push((text.to_owned(), bounds));
    }
    fn traverse(&mut self, operate: &mut dyn FnMut(&mut dyn widget::Operation)) {
        operate(self);
    }
}

struct Flow {
    app: App,
    runtime: tokio::runtime::Runtime,
    tasks: SelectAll<iced::futures::stream::BoxStream<'static, iced_runtime::Action<Message>>>,
}

impl Flow {
    /// Start a real server in this (sandboxed) process and boot the app against it.
    fn start() -> Self {
        assert!(
            std::env::var_os(SANDBOX_ENV).is_some(),
            "flows must run sandboxed"
        );
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(password_manager::server::server(port, 10, 0, false))
                .expect("test server failed");
        });
        let client = AuthenticatedClient::new(port);
        let ready = Instant::now() + Duration::from_secs(10);
        while backend::attach(&client).is_err() {
            assert!(Instant::now() < ready, "test server did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
        let (app, task) = App::boot(Config::default(), client, None);
        let mut flow = Self {
            app,
            runtime: tokio::runtime::Runtime::new().unwrap(),
            tasks: SelectAll::new(),
        };
        flow.queue(task);
        flow.settle();
        flow
    }

    fn queue(&mut self, task: Task<Message>) {
        if let Some(stream) = iced_runtime::task::into_stream(task) {
            self.tasks.push(stream);
        }
    }

    /// Deliver a message as if the matching control produced it, then settle.
    fn send(&mut self, message: Message) {
        let task = self.app.update(message);
        self.queue(task);
        self.settle();
    }

    /// Run queued tasks until none remain, feeding their messages back into
    /// `update`. Window, widget and system actions have no window to act on.
    fn settle(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let next = self
                .runtime
                .block_on(async { tokio::time::timeout(remaining, self.tasks.next()).await });
            match next {
                Ok(Some(iced_runtime::Action::Output(message))) => {
                    let task = self.app.update(message);
                    self.queue(task);
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => panic!(
                    "the app did not settle within 60 seconds; notice: {}",
                    self.app.notice
                ),
            }
        }
        // Empty `SelectAll` reports the end of the stream; reset it for new tasks.
        self.tasks = SelectAll::new();
    }

    fn layout(
        &self,
    ) -> (
        iced::Renderer,
        Element<'_, Message>,
        widget::Tree,
        layout::Node,
    ) {
        use renderer::Renderer as _;
        let mut renderer = iced::Renderer::new(iced::Font::DEFAULT, iced::Pixels(16.0));
        renderer.reset(Rectangle::with_size(Size::new(WIDTH, HEIGHT)));
        let mut element = self.app.view();
        let mut tree = widget::Tree::new(&element);
        let node = element.as_widget_mut().layout(
            &mut tree,
            &renderer,
            &layout::Limits::new(Size::ZERO, Size::new(WIDTH, HEIGHT)),
        );
        (renderer, element, tree, node)
    }

    /// Every text on screen with its bounds.
    fn texts(&self) -> Vec<(String, Rectangle)> {
        let (renderer, mut element, mut tree, node) = self.layout();
        let mut texts = Texts::default();
        element.as_widget_mut().operate(
            &mut tree,
            layout::Layout::new(&node),
            &renderer,
            &mut texts,
        );
        texts.0
    }

    fn shows(&self, wanted: &str) -> bool {
        self.texts().iter().any(|(text, _)| text.contains(wanted))
    }

    #[track_caller]
    fn expect_shows(&self, wanted: &str) {
        assert!(
            self.shows(wanted),
            "expected the screen to show {wanted:?}; it shows {:?} (notice: {})",
            self.texts().into_iter().map(|(t, _)| t).collect::<Vec<_>>(),
            self.app.notice
        );
    }

    /// Press and release the mouse at `point`; returns the messages produced.
    fn press(&self, point: iced::Point) -> Vec<Message> {
        let (renderer, mut element, mut tree, node) = self.layout();
        let viewport = Rectangle::with_size(Size::new(WIDTH, HEIGHT));
        let mut messages = Vec::new();
        for event in [
            iced::Event::Mouse(mouse::Event::CursorMoved { position: point }),
            iced::Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)),
            iced::Event::Mouse(mouse::Event::ButtonReleased(mouse::Button::Left)),
        ] {
            element.as_widget_mut().update(
                &mut tree,
                &event,
                layout::Layout::new(&node),
                mouse::Cursor::Available(point),
                &renderer,
                &mut iced::advanced::clipboard::Null,
                &mut iced::advanced::Shell::new(&mut messages),
                &viewport,
            );
        }
        messages
    }

    /// Click the control labelled exactly `label` through the rendered view. The
    /// same words may also appear as a heading; the first match that responds wins.
    #[track_caller]
    fn click(&mut self, label: &str) {
        let texts = self.texts();
        let matches: Vec<Rectangle> = texts
            .iter()
            .filter(|(text, _)| text == label)
            .map(|(_, bounds)| *bounds)
            .collect();
        assert!(
            !matches.is_empty(),
            "no control labelled {label:?}; the screen shows {:?}",
            texts.iter().map(|(t, _)| t).collect::<Vec<_>>()
        );
        let messages = matches
            .iter()
            .map(|bounds| self.press(bounds.center()))
            .find(|messages| !messages.is_empty());
        let Some(messages) = messages else {
            panic!(
                "clicking {label:?} did nothing (disabled, or not a control); request state \
                 {:?}, pending operation {:?}, notice {:?}",
                self.app.request_state,
                self.app.recovery.id(),
                self.app.notice
            );
        };
        for message in messages {
            self.send(message);
        }
    }

    fn type_master(&mut self, password: &str) {
        self.send(Message::Master(password.to_owned().into()));
    }

    fn item_names(&self) -> Vec<String> {
        self.app
            .items
            .iter()
            .map(|item| item.name.clone())
            .collect()
    }
}

fn create_vault(flow: &mut Flow) {
    flow.expect_shows("Create your first vault");
    flow.click("Create your first vault");
    flow.type_master(MASTER);
    flow.send(Message::ConfirmMaster(MASTER.to_owned().into()));
    flow.click("Create vault");
    assert!(
        flow.app.connection.session.is_some(),
        "the new vault should be open: {}",
        flow.app.notice
    );
}

fn add_login(flow: &mut Flow, name: &str, username: &str, password: &str) {
    flow.click(if flow.app.items.is_empty() {
        "Add your first item"
    } else {
        "Add item"
    });
    flow.send(Message::Name(name.into()));
    flow.send(Message::Username(username.into()));
    flow.send(Message::Password(password.to_owned().into()));
    flow.click("Save item");
    assert!(
        flow.item_names().iter().any(|item| item == name),
        "{name} was not saved: {}",
        flow.app.notice
    );
}

#[test]
fn create_a_vault_add_items_and_find_them() {
    sandboxed("create_a_vault_add_items_and_find_them", || {
        let mut flow = Flow::start();
        create_vault(&mut flow);
        flow.expect_shows("Add your first item");
        add_login(
            &mut flow,
            "Maple Mail",
            "alice@example.test",
            "synthetic-mail-1",
        );
        add_login(&mut flow, "Code Garden", "alice", "synthetic-code-1");
        flow.expect_shows("Maple Mail");
        flow.expect_shows("Code Garden");
        // The last saved item stays open beside the list; close it to see the list alone.
        flow.send(Message::Navigate(Navigate::Close));
        flow.send(Message::Search("maple".into()));
        flow.expect_shows("Maple Mail");
        assert!(!flow.shows("Code Garden"), "search should hide other items");
        // An opened item keeps its password hidden until revealed.
        flow.click("Maple Mail");
        assert_eq!(
            flow.app.item.as_ref().map(|item| item.name.as_str()),
            Some("Maple Mail")
        );
        assert!(!flow.shows("synthetic-mail-1"));
        flow.click("Reveal for 15 seconds");
        flow.expect_shows("synthetic-mail-1");
        flow.click("Hide secrets");
        assert!(!flow.shows("synthetic-mail-1"));
    });
}

#[test]
fn edit_lock_and_unlock_keep_the_change() {
    sandboxed("edit_lock_and_unlock_keep_the_change", || {
        let mut flow = Flow::start();
        create_vault(&mut flow);
        add_login(
            &mut flow,
            "Maple Mail",
            "alice@example.test",
            "synthetic-mail-1",
        );
        flow.click("Edit item");
        flow.send(Message::Username("bob@example.test".into()));
        flow.click("Save item");
        flow.expect_shows("bob@example.test");

        flow.click("Lock vault");
        assert!(flow.app.connection.session.is_none(), "{}", flow.app.notice);
        assert!(flow.app.items.is_empty(), "locking clears the item list");

        flow.type_master("not the master password");
        flow.click("Unlock vault");
        assert!(flow.app.connection.session.is_none());
        assert!(flow.app.ui.notice_error, "a wrong password is reported");

        flow.type_master(MASTER);
        flow.click("Unlock vault");
        assert!(flow.app.connection.session.is_some(), "{}", flow.app.notice);
        flow.expect_shows("Maple Mail");
        flow.click("Maple Mail");
        assert_eq!(
            flow.app
                .item
                .as_ref()
                .and_then(|item| item.username.as_deref()),
            Some("bob@example.test"),
            "the edit survives locking: {}",
            flow.app.notice
        );
    });
}

#[test]
fn trash_and_undo_restore_an_item() {
    sandboxed("trash_and_undo_restore_an_item", || {
        let mut flow = Flow::start();
        create_vault(&mut flow);
        add_login(
            &mut flow,
            "Maple Mail",
            "alice@example.test",
            "synthetic-mail-1",
        );
        flow.click("Move to trash…");
        flow.click("Move to trash");
        assert!(flow.item_names().is_empty(), "{}", flow.app.notice);
        flow.click("Undo deletion");
        assert_eq!(flow.item_names(), ["Maple Mail"], "{}", flow.app.notice);
    });
}

#[test]
fn an_edit_that_races_another_client_is_kept_for_review() {
    sandboxed(
        "an_edit_that_races_another_client_is_kept_for_review",
        || {
            use password_manager::types::{EntryChanges, EntryUpdate, Target, TypedUpdate};
            let mut flow = Flow::start();
            create_vault(&mut flow);
            add_login(
                &mut flow,
                "Maple Mail",
                "alice@example.test",
                "synthetic-mail-1",
            );
            let id = flow.app.item.as_ref().unwrap().id;
            flow.click("Edit item");
            flow.send(Message::Username("bob@example.test".into()));

            // Another client (the CLI, the browser) changes the same item meanwhile.
            let other = AuthenticatedClient::new(flow.app.connection.client.port);
            backend::request(
                &other,
                RequestEnvelope::new(ServerCommand::Update(TypedUpdate::from(EntryUpdate {
                    target: Target::Id(id),
                    update: EntryChanges {
                        notes: Some("changed in another client".into()),
                        ..Default::default()
                    },
                    password: None,
                }))),
            )
            .expect("the other client's update");

            flow.click("Save item");
            flow.expect_shows("This item changed in another client");
            flow.click("Review latest version");
            flow.click("Reapply my edits to this version");
            flow.click("Save item");
            let item = flow.app.item.as_ref().expect("the saved item stays open");
            assert_eq!(
                item.username.as_deref(),
                Some("bob@example.test"),
                "{}",
                flow.app.notice
            );
            assert_eq!(
                item.notes.as_ref().map(|notes| notes.expose()),
                Some("changed in another client"),
                "fields this client did not edit keep the other client's value"
            );
        },
    );
}

#[test]
fn saved_settings_reach_the_config_file() {
    sandboxed("saved_settings_reach_the_config_file", || {
        let mut flow = Flow::start();
        flow.send(Message::Tab(Tab::Settings));
        flow.send(Message::SettingChanged(SettingsField::Length, "24".into()));
        flow.click("Save settings");
        assert_eq!(flow.app.conf.genpass.length, 24, "{}", flow.app.notice);
        let directory = std::path::PathBuf::from(std::env::var_os("PM_CONFIG_DIR").unwrap());
        let saved = std::fs::read_dir(&directory)
            .unwrap()
            .filter_map(|entry| std::fs::read_to_string(entry.unwrap().path()).ok())
            .any(|text| text.contains("length = 24"));
        assert!(
            saved,
            "no file in the sandboxed config folder records the new length"
        );
    });
}
