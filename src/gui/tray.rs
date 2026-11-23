//! A system tray icon on Linux (the freedesktop StatusNotifierItem protocol,
//! shown by Waybar, KDE, GNOME with AppIndicator, and others). Clicking it
//! brings the window forward; its menu offers Open, Lock vault and Close. The
//! tooltip and menu follow the vault's state (unlocked, locked, service stopped).
//! Without a tray host on the session bus, nothing is shown.

use super::Message;
use std::collections::HashMap;
use std::sync::Mutex;
use zbus::interface;
use zbus::{OwnedVariant as OwnedValue, Structure, Variant as Value};

type Output = iced::futures::channel::mpsc::Sender<Message>;

/// What the tray shows: 0 service stopped or unknown, 1 locked, 2 unlocked.
static STATE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

/// Called by the window whenever the connection or lock state changes.
pub fn set_state(running: bool, unlocked: bool) {
    let state = match (running, unlocked) {
        (false, _) => 0,
        (true, false) => 1,
        (true, true) => 2,
    };
    STATE.store(state, std::sync::atomic::Ordering::Relaxed);
}

fn state() -> u8 {
    STATE.load(std::sync::atomic::Ordering::Relaxed)
}
/// StatusNotifierItem `ToolTip`: icon name, pixmaps, title, description.
type ToolTip = (String, Vec<(i32, i32, Vec<u8>)>, String, String);
/// dbusmenu layout node: id, properties, children.
type Layout = (i32, HashMap<String, OwnedValue>, Vec<OwnedValue>);

/// Tray events for as long as the window runs.
pub fn events() -> impl iced::futures::Stream<Item = Message> {
    iced::stream::channel(4, async move |output| {
        // A missing tray host or session bus simply means no tray icon.
        let _connection = serve(output).await.ok();
        std::future::pending::<()>().await
    })
}

async fn serve(output: Output) -> zbus::Result<zbus::Connection> {
    let name = format!("org.kde.StatusNotifierItem-{}-1", std::process::id());
    let sender = std::sync::Arc::new(Mutex::new(output));
    let connection = zbus::connection::Builder::session()
        .name(name.as_str())
        .serve_at(
            "/StatusNotifierItem",
            Item {
                sender: sender.clone(),
            },
        )
        .serve_at("/MenuBar", Menu { sender })
        .build()
        .await?;
    // Tray hosts cache properties; signal changes so the tooltip and menu stay current.
    let watcher = connection.clone();
    tokio::spawn(async move {
        let mut shown = state();
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(750)).await;
            let now = state();
            if now == shown {
                continue;
            }
            shown = now;
            if let Ok(item) = watcher
                .object_server()
                .interface::<_, Item>("/StatusNotifierItem")
                .await
            {
                let _ = Item::new_tool_tip(item.signal_emitter()).await;
                let _ = Item::new_title(item.signal_emitter()).await;
            }
            if let Ok(menu) = watcher
                .object_server()
                .interface::<_, Menu>("/MenuBar")
                .await
            {
                let _ = Menu::layout_updated(menu.signal_emitter(), u32::from(now) + 2, 0).await;
            }
        }
    });
    connection
        .call_method(
            Some("org.kde.StatusNotifierWatcher"),
            "/StatusNotifierWatcher",
            Some("org.kde.StatusNotifierWatcher"),
            "RegisterStatusNotifierItem",
            &(name.as_str(),),
        )
        .await?;
    Ok(connection)
}

fn send(sender: &Mutex<Output>, message: Message) {
    if let Ok(mut sender) = sender.lock() {
        let _ = sender.try_send(message);
    }
}

struct Item {
    sender: std::sync::Arc<Mutex<Output>>,
}

#[interface(name = "org.kde.StatusNotifierItem")]
impl Item {
    #[zbus(property)]
    fn category(&self) -> &str {
        "ApplicationStatus"
    }
    #[zbus(property)]
    fn id(&self) -> &str {
        "password-manager"
    }
    #[zbus(property)]
    fn title(&self) -> &str {
        match state() {
            2 => "Password Manager · Unlocked",
            1 => "Password Manager · Locked",
            _ => "Password Manager · Service stopped",
        }
    }
    #[zbus(signal)]
    async fn new_title(emitter: &zbus::object_server::SignalEmitter<'_>) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn new_tool_tip(emitter: &zbus::object_server::SignalEmitter<'_>) -> zbus::Result<()>;
    #[zbus(property)]
    fn status(&self) -> &str {
        "Active"
    }
    #[zbus(property)]
    fn icon_name(&self) -> &str {
        ""
    }
    /// The app icon as ARGB32 in network byte order.
    #[zbus(property)]
    fn icon_pixmap(&self) -> Vec<(i32, i32, Vec<u8>)> {
        vec![(64, 64, argb_icon())]
    }
    #[zbus(property)]
    fn tool_tip(&self) -> ToolTip {
        (
            String::new(),
            Vec::new(),
            match state() {
                2 => "Password Manager · Unlocked",
                1 => "Password Manager · Locked",
                _ => "Password Manager · Service stopped",
            }
            .into(),
            match state() {
                2 => "Click to open. Middle-click or use the menu to lock the vault.",
                1 => "Click to open the app and unlock your vault.",
                _ => "Click to open the app and start the service.",
            }
            .into(),
        )
    }
    #[zbus(property)]
    fn menu(&self) -> zbus::OwnedObjectPath {
        zbus::OwnedObjectPath::try_from("/MenuBar").expect("valid object path")
    }
    #[zbus(property)]
    fn item_is_menu(&self) -> bool {
        false
    }
    fn activate(&self, _x: i32, _y: i32) {
        send(
            &self.sender,
            Message::Raise(super::instance::Request::Focus),
        );
    }
    fn secondary_activate(&self, _x: i32, _y: i32) {
        send(&self.sender, Message::Lock);
    }
    fn context_menu(&self, _x: i32, _y: i32) {}
    fn scroll(&self, _delta: i32, _orientation: &str) {}
}

fn argb_icon() -> Vec<u8> {
    include_bytes!("../../assets/password-manager-64.rgba")
        .chunks_exact(4)
        .flat_map(|pixel| [pixel[3], pixel[0], pixel[1], pixel[2]])
        .collect()
}

/// The tray menu (the com.canonical.dbusmenu protocol).
struct Menu {
    sender: std::sync::Arc<Mutex<Output>>,
}

// "Close window" says what it does: the background service follows its own close setting.
const ENTRIES: [(i32, &str); 3] = [
    (1, "Open Password Manager"),
    (2, "Lock vault"),
    (3, "Close window"),
];

fn properties(id: i32, label: &str) -> HashMap<String, OwnedValue> {
    let mut map = HashMap::new();
    if let Ok(value) = OwnedValue::try_from(Value::from(label)) {
        map.insert("label".to_owned(), value);
    }
    // Locking only applies while the vault is unlocked.
    let enabled = id != 2 || state() == 2;
    if let Ok(value) = OwnedValue::try_from(Value::from(enabled)) {
        map.insert("enabled".to_owned(), value);
    }
    map
}

fn entry(id: i32, label: &str) -> Option<OwnedValue> {
    let empty: Vec<Value<'static>> = Vec::new();
    let structure = Structure::builder()
        .add_field(id)
        .add_field(properties(id, label))
        .add_field(empty)
        .build()
        .ok()?;
    OwnedValue::try_from(Value::Structure(structure)).ok()
}

#[interface(name = "com.canonical.dbusmenu")]
impl Menu {
    #[zbus(property)]
    fn version(&self) -> u32 {
        3
    }
    #[zbus(property)]
    fn text_direction(&self) -> &str {
        "ltr"
    }
    #[zbus(property)]
    fn status(&self) -> &str {
        "normal"
    }
    #[zbus(property)]
    fn icon_theme_path(&self) -> Vec<String> {
        Vec::new()
    }

    #[zbus(signal)]
    async fn layout_updated(
        emitter: &zbus::object_server::SignalEmitter<'_>,
        revision: u32,
        parent: i32,
    ) -> zbus::Result<()>;

    fn get_layout(
        &self,
        _parent_id: i32,
        _recursion_depth: i32,
        _property_names: Vec<String>,
    ) -> (u32, Layout) {
        let mut root = HashMap::new();
        if let Ok(value) = OwnedValue::try_from(Value::from("submenu")) {
            root.insert("children-display".to_owned(), value);
        }
        let children = ENTRIES
            .iter()
            .filter_map(|(id, label)| entry(*id, label))
            .collect();
        (u32::from(state()) + 2, (0, root, children))
    }

    fn get_group_properties(
        &self,
        ids: Vec<i32>,
        _property_names: Vec<String>,
    ) -> Vec<(i32, HashMap<String, OwnedValue>)> {
        ENTRIES
            .iter()
            .filter(|(id, _)| ids.is_empty() || ids.contains(id))
            .map(|(id, label)| (*id, properties(*id, label)))
            .collect()
    }

    fn get_property(&self, id: i32, name: &str) -> zbus::fdo::Result<OwnedValue> {
        ENTRIES
            .iter()
            .find(|(entry, _)| *entry == id)
            .and_then(|(entry, label)| properties(*entry, label).remove(name))
            .ok_or_else(|| zbus::fdo::Error::InvalidArgs("unknown menu property".into()))
    }

    fn event(&self, id: i32, event_id: &str, _data: OwnedValue, _timestamp: u32) {
        if event_id != "clicked" {
            return;
        }
        match id {
            1 => send(
                &self.sender,
                Message::Raise(super::instance::Request::Focus),
            ),
            2 => send(&self.sender, Message::Lock),
            3 => send(&self.sender, Message::Quit),
            _ => {}
        }
    }

    fn event_group(&self, events: Vec<(i32, String, OwnedValue, u32)>) -> Vec<i32> {
        for (id, event_id, data, timestamp) in events {
            self.event(id, &event_id, data, timestamp);
        }
        Vec::new()
    }

    fn about_to_show(&self, _id: i32) -> bool {
        false
    }

    fn about_to_show_group(&self, _ids: Vec<i32>) -> (Vec<i32>, Vec<i32>) {
        (Vec::new(), Vec::new())
    }
}
