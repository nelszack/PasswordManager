use super::*;
use iced::{Color, theme::Palette};
use password_manager::config::Appearance;

/// Tool results (search, trash, audit) per page.
pub(super) const PAGE_SIZE: usize = 50;
/// Vault list items per page; long enough that most vaults scroll as one list.
pub(super) const ITEM_PAGE_SIZE: usize = 200;

/// Shared bounds for the item list and tool results. Empty lists retain page 1.
pub(super) struct Page {
    pub index: usize,
    pub pages: usize,
    pub range: std::ops::Range<usize>,
}
impl Page {
    pub fn new(requested: usize, total: usize) -> Self {
        Self::sized(requested, total, PAGE_SIZE)
    }
    /// The vault item list's page window.
    pub fn items(requested: usize, total: usize) -> Self {
        Self::sized(requested, total, ITEM_PAGE_SIZE)
    }
    fn sized(requested: usize, total: usize, size: usize) -> Self {
        let pages = total.div_ceil(size).max(1);
        let index = requested.min(pages - 1);
        let start = index * size;
        Self {
            index,
            pages,
            range: start..start.saturating_add(size).min(total),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum SettingsSection {
    #[default]
    Appearance,
    Vault,
    Security,
    Passwords,
    Recovery,
    Connection,
    Sync,
}

impl SettingsSection {
    pub const ALL: [Self; 7] = [
        Self::Appearance,
        Self::Vault,
        Self::Security,
        Self::Passwords,
        Self::Recovery,
        Self::Sync,
        Self::Connection,
    ];
    pub fn title(self) -> &'static str {
        match self {
            Self::Appearance => "Appearance",
            Self::Vault => "This vault",
            Self::Security => "Security",
            Self::Passwords => "Passwords",
            Self::Recovery => "Recovery",
            Self::Connection => "Browser & service",
            Self::Sync => "Sync",
        }
    }
}

impl std::fmt::Display for SettingsSection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.title())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ScaleChoice(pub u16);
impl std::fmt::Display for ScaleChoice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self.0 {
            // In increasing order, so each step reads larger than the last.
            115 => "Large",
            130 => "Larger",
            150 => "Extra large",
            175 => "Huge",
            200 => "Largest",
            _ => "Standard",
        };
        write!(f, "{}% · {label}", self.0)
    }
}

#[derive(Default)]
struct ChoiceCache {
    vaults: Vec<String>,
    names: std::collections::BTreeMap<String, String>,
    choices: Vec<vault_names::Choice>,
}
pub(super) struct State {
    choices: std::cell::RefCell<ChoiceCache>,
    matching: std::cell::RefCell<Option<MatchingItems>>,
    /// Distinct tags of the loaded items, sorted; rebuilt when the items change.
    tags: std::cell::RefCell<Option<Vec<String>>>,
    search_text: std::cell::RefCell<std::collections::HashMap<usize, SearchText>>,
    pub progress: String,
    pub progress_started: Option<Instant>,
    pub reverse_items: bool,
    pub item_page: usize,
    pub confirm_close: Option<iced::window::Id>,
    /// Asking whether to lock before closing this window.
    pub confirm_lock_close: Option<iced::window::Id>,
    /// Close this window once the requested lock completes.
    pub close_after_lock: Option<iced::window::Id>,
    pub transfer_generated: bool,
    pub width: f32,
    pub height: f32,
    pub unlock_advanced: bool,
    pub editor_advanced: bool,
    pub editor_authenticators: bool,
    pub editor_show_secret: bool,
    pub generator_advanced: bool,
    pub shortcuts: bool,
    pub troubleshooting: bool,
    pub settings_section: SettingsSection,
    pub kind: Option<ItemKind>,
    pub tag: Option<String>,
    pub favorites_only: bool,
    /// SSH agent signatures waiting for a decision.
    pub ssh_requests: Vec<password_manager::protocol::SshRequest>,
    /// Browser passkey requests waiting for the person to confirm.
    pub passkey_requests: Vec<password_manager::protocol::PasskeyRequest>,
    /// The master password or passkey PIN typed to confirm the first request.
    pub passkey_secret: SecretString,
    /// A passkey PIN is set for the unlocked vault on this device.
    pub passkey_pin: bool,
    /// New passkey PIN and its confirmation in Settings → Security.
    pub pin_new: SecretString,
    pub pin_confirm: SecretString,
    /// A one-time notice from the service, such as a vault format upgrade.
    pub format_notice: Option<String>,
    pub notice_error: bool,
    /// The open item's notes are shown (hidden again with other secrets).
    pub notes_visible: bool,
    pub confirm_stop: bool,
    /// An item to show as soon as the vault is unlocked and its list loads.
    pub open_after_unlock: Option<usize>,
    /// Saved settings only apply after the service restarts.
    pub restart_needed: bool,
    /// Start the service again once the current stop finishes.
    pub restart_after_stop: bool,
    pub active_vault: Option<(String, String)>,
    pub undo_trash: Option<(usize, String)>,
    pub vault_name: String,
    pub master_error: Option<&'static str>,
    /// Selection mode in the item list, and the chosen item IDs.
    pub selecting: bool,
    pub selected: std::collections::BTreeSet<usize>,
    /// The tag typed for "Add tag" in selection mode.
    pub bulk_tag: String,
    /// A bulk move to trash waiting for confirmation.
    pub bulk_confirm: bool,
    /// A bulk change in progress: one request at a time.
    pub bulk: Option<super::Bulk>,
    /// The master password is shown while typing.
    pub master_visible: bool,
    /// The last unlock or create failure, shown under the password field.
    pub unlock_error: Option<String>,
    /// The operating system prefers a light theme ("Match system").
    pub system_light: bool,
    /// Strength of the new master password, scored when it changes.
    pub master_strength: Option<super::model::Strength>,
    /// A generated master passphrase shown once so it can be written down.
    pub suggested_master: Option<SecretString>,
    pub saved_item: Option<SavedItem>,
}

/// Public metadata only, used to identify a confirmed new save without keeping
/// its password or guessing between concurrent additions.
pub(super) struct SavedItem {
    pub name: String,
    pub kind: ItemKind,
    pub previous_ids: std::collections::HashSet<usize>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            choices: std::cell::RefCell::default(),
            matching: std::cell::RefCell::default(),
            tags: std::cell::RefCell::default(),
            search_text: std::cell::RefCell::default(),
            progress: String::new(),
            progress_started: None,
            reverse_items: false,
            item_page: 0,
            confirm_close: None,
            confirm_lock_close: None,
            close_after_lock: None,
            transfer_generated: false,
            width: 1060.0,
            height: 760.0,
            unlock_advanced: false,
            editor_advanced: false,
            editor_authenticators: false,
            editor_show_secret: false,
            generator_advanced: false,
            shortcuts: false,
            troubleshooting: false,
            settings_section: SettingsSection::default(),
            kind: None,
            tag: None,
            favorites_only: false,
            ssh_requests: Vec::new(),
            passkey_requests: Vec::new(),
            passkey_secret: SecretString::default(),
            passkey_pin: false,
            pin_new: SecretString::default(),
            pin_confirm: SecretString::default(),
            format_notice: None,
            notice_error: false,
            notes_visible: false,
            confirm_stop: false,
            open_after_unlock: None,
            restart_needed: false,
            restart_after_stop: false,
            master_error: None,
            system_light: false,
            unlock_error: None,
            master_visible: false,
            selecting: false,
            selected: std::collections::BTreeSet::new(),
            bulk_tag: String::new(),
            bulk_confirm: false,
            bulk: None,
            master_strength: None,
            suggested_master: None,
            saved_item: None,
            active_vault: None,
            undo_trash: None,
            vault_name: "Personal vault".into(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Disclosure {
    Unlock,
    Editor,
    Authenticators,
    Generator,
    Shortcuts,
    Troubleshooting,
}

impl App {
    pub(super) fn compact(&self) -> bool {
        self.ui.width < 900.0
    }

    pub(super) fn theme(&self) -> Theme {
        let appearance = match self.settings.appearance {
            Appearance::System if self.ui.system_light => Appearance::Light,
            Appearance::System => Appearance::Dark,
            chosen => chosen,
        };
        match appearance {
            Appearance::System => unreachable!("resolved above"),
            Appearance::Light => Theme::custom_with_fn(
                "Daylight",
                Palette {
                    background: Color::from_rgb8(246, 248, 252),
                    text: Color::from_rgb8(25, 35, 52),
                    primary: Color::from_rgb8(40, 80, 190),
                    success: Color::from_rgb8(22, 112, 75),
                    warning: Color::from_rgb8(140, 85, 0),
                    danger: Color::from_rgb8(178, 35, 54),
                },
                |palette| {
                    use iced::theme::palette::{Extended, Pair};
                    let mut extended = Extended::generate(palette);
                    extended.background.weak =
                        Pair::new(blend(palette.background, palette.text, 0.035), palette.text);
                    let edge = blend(palette.background, palette.text, 0.60);
                    extended.background.strong = Pair {
                        color: edge,
                        text: surface_text(edge),
                    };
                    extended
                },
            ),
            Appearance::Dark => Theme::custom_with_fn(
                "Midnight",
                Palette {
                    background: Color::from_rgb8(18, 23, 34),
                    text: Color::from_rgb8(230, 236, 247),
                    primary: Color::from_rgb8(156, 183, 255),
                    success: Color::from_rgb8(109, 216, 173),
                    warning: Color::from_rgb8(246, 199, 111),
                    danger: Color::from_rgb8(255, 150, 164),
                },
                |palette| {
                    use iced::theme::palette::{Extended, Pair};
                    let mut extended = Extended::generate(palette);
                    extended.background.weak =
                        Pair::new(blend(palette.background, palette.text, 0.035), palette.text);
                    let edge = blend(palette.background, palette.text, 0.45);
                    extended.background.strong = Pair {
                        color: edge,
                        text: surface_text(edge),
                    };
                    extended
                },
            ),
            Appearance::HighContrast => Theme::custom_with_fn(
                "High contrast",
                Palette {
                    background: Color::BLACK,
                    text: Color::WHITE,
                    primary: Color::from_rgb8(155, 220, 255),
                    success: Color::from_rgb8(140, 255, 175),
                    warning: Color::from_rgb8(255, 229, 119),
                    danger: Color::from_rgb8(255, 160, 160),
                },
                |palette| {
                    use iced::theme::palette::{Extended, Pair};
                    let mut extended = Extended::generate(palette);
                    extended.background.weak =
                        Pair::new(Color::from_rgb8(15, 15, 15), Color::WHITE);
                    extended.background.strong =
                        Pair::new(Color::from_rgb8(180, 180, 180), Color::BLACK);
                    extended
                },
            ),
        }
    }

    pub(super) fn scale_factor(&self) -> f32 {
        f32::from(self.settings.scale.clamp(100, 200)) / 100.0
    }

    pub(super) fn vault_choices(&self) -> Vec<vault_names::Choice> {
        let mut cache = self.ui.choices.borrow_mut();
        if cache.vaults == self.connection.vaults && cache.names == self.names.0 {
            return cache.choices.clone();
        }
        let labels: Vec<_> = self
            .connection
            .vaults
            .iter()
            .enumerate()
            .map(|(index, id)| self.names.label_at(id, index, self.connection.vaults.len()))
            .collect();
        let mut counts = std::collections::HashMap::new();
        for label in &labels {
            *counts.entry(label.as_str()).or_insert(0usize) += 1;
        }
        let choices: Vec<_> = self
            .connection
            .vaults
            .iter()
            .zip(&labels)
            .enumerate()
            .map(|(index, (id, label))| vault_names::Choice {
                id: id.clone(),
                label: if counts[label.as_str()] > 1 {
                    format!("{label} · {}", index + 1)
                } else {
                    label.clone()
                },
            })
            .collect();
        *cache = ChoiceCache {
            vaults: self.connection.vaults.clone(),
            names: self.names.0.clone(),
            choices: choices.clone(),
        };
        choices
    }

    pub(super) fn apply_item_changes(
        &mut self,
        changes: &password_manager::vault::ItemChanges,
    ) -> bool {
        if self.items_revision != Some(changes.base_revision)
            || changes.revision <= changes.base_revision
        {
            return false;
        }
        let replaced: std::collections::HashSet<_> = changes
            .removed
            .iter()
            .copied()
            .chain(changes.items.iter().map(|item| item.id))
            .collect();
        self.items.retain(|item| !replaced.contains(&item.id));
        for item in &changes.items {
            let key = item.name.to_lowercase();
            let index = self.items.partition_point(|existing| {
                (&existing.name.to_lowercase(), existing.id) < (&key, item.id)
            });
            self.items.insert(index, item.clone());
        }
        self.ui.matching.get_mut().take();
        self.ui.tags.get_mut().take();
        for id in replaced {
            self.ui.search_text.get_mut().remove(&id);
        }
        self.vault_revision = Some(changes.revision);
        self.items_revision = Some(changes.revision);
        true
    }

    pub(super) fn replace_items(&mut self, items: Vec<ItemSummary>) {
        self.ui.matching.get_mut().take();
        self.ui.tags.get_mut().take();
        self.ui.search_text.get_mut().clear();
        self.items = items;
    }

    /// Distinct tags across the loaded items (the first spelling of each,
    /// ignoring ASCII case), sorted case-insensitively. Views ask for this on
    /// every redraw, so it is computed once per change to the items.
    pub(super) fn available_tags(&self) -> std::cell::Ref<'_, Vec<String>> {
        if self.ui.tags.borrow().is_none() {
            let mut seen = std::collections::HashSet::new();
            let mut tags: Vec<String> = self
                .items
                .iter()
                .flat_map(|item| &item.tags)
                .filter(|tag| seen.insert(tag.to_ascii_lowercase()))
                .cloned()
                .collect();
            tags.sort_by_cached_key(|tag| tag.to_lowercase());
            *self.ui.tags.borrow_mut() = Some(tags);
        }
        std::cell::Ref::map(self.ui.tags.borrow(), |tags| tags.as_ref().unwrap())
    }

    pub(super) fn matching_items(&self) -> std::cell::Ref<'_, Vec<usize>> {
        let mut cache = self.ui.matching.borrow_mut();
        if cache.as_ref().is_none_or(|cached| {
            cached.query.as_str() != self.query
                || cached.kind != self.ui.kind
                || cached.tag != self.ui.tag
                || cached.favorites_only != self.ui.favorites_only
                || cached.source_len != self.items.len()
        }) {
            let query = zeroize::Zeroizing::new(self.query.trim().to_lowercase());
            let mut search_text = self.ui.search_text.borrow_mut();
            let indices = self
                .items
                .iter()
                .enumerate()
                .filter_map(|(index, item)| {
                    (self.ui.kind.is_none_or(|kind| kind == item.kind)
                        && (!self.ui.favorites_only || item.favorite)
                        && self.ui.tag.as_ref().is_none_or(|tag| {
                            item.tags.iter().any(|t| t.eq_ignore_ascii_case(tag))
                        })
                        && (query.is_empty() || {
                            let text = search_text
                                .entry(item.id)
                                .or_insert_with(|| SearchText::new(item));
                            if text.revision != item.revision {
                                *text = SearchText::new(item);
                            }
                            text.values
                                .iter()
                                .any(|value| value.contains(query.as_str()))
                        }))
                    .then_some(index)
                })
                .collect();
            *cache = Some(MatchingItems {
                query: zeroize::Zeroizing::new(self.query.clone()),
                kind: self.ui.kind,
                tag: self.ui.tag.clone(),
                favorites_only: self.ui.favorites_only,
                source_len: self.items.len(),
                indices,
            });
        }
        drop(cache);
        std::cell::Ref::map(self.ui.matching.borrow(), |cached| {
            &cached.as_ref().unwrap().indices
        })
    }
}

struct MatchingItems {
    query: zeroize::Zeroizing<String>,
    kind: Option<ItemKind>,
    tag: Option<String>,
    favorites_only: bool,
    source_len: usize,
    indices: Vec<usize>,
}

struct SearchText {
    revision: u64,
    values: Vec<zeroize::Zeroizing<String>>,
}
impl SearchText {
    fn new(item: &ItemSummary) -> Self {
        Self {
            revision: item.revision,
            values: std::iter::once(item.name.as_str())
                .chain(item.username.as_deref())
                .chain(item.urls.iter().map(String::as_str))
                .chain(item.tags.iter().map(String::as_str))
                .map(|value| zeroize::Zeroizing::new(value.to_lowercase()))
                .collect(),
        }
    }
}

fn surface_text(color: Color) -> Color {
    let linear = |value: f32| {
        if value <= 0.04045 {
            value / 12.92
        } else {
            ((value + 0.055) / 1.055).powf(2.4)
        }
    };
    let luminance = 0.2126 * linear(color.r) + 0.7152 * linear(color.g) + 0.0722 * linear(color.b);
    if luminance > 0.179 {
        Color::BLACK
    } else {
        Color::WHITE
    }
}

pub(super) fn blend(background: Color, foreground: Color, amount: f32) -> Color {
    Color::from_rgb(
        background.r * (1.0 - amount) + foreground.r * amount,
        background.g * (1.0 - amount) + foreground.g * amount,
        background.b * (1.0 - amount) + foreground.b * amount,
    )
}

pub(super) fn display_date(value: &str) -> String {
    value
        .parse::<jiff::Timestamp>()
        .map(|date| {
            date.to_zoned(jiff::tz::TimeZone::system())
                .strftime("%b %d, %Y · %H:%M")
                .to_string()
        })
        .unwrap_or_else(|_| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn page_windows_clamp_empty_partial_and_extreme_requests() {
        for (requested, total, index, pages, range) in [
            (8, 0, 0, 1, 0..0),
            (0, 50, 0, 1, 0..50),
            (1, 51, 1, 2, 50..51),
            (usize::MAX, 100, 1, 2, 50..100),
        ] {
            let page = Page::new(requested, total);
            assert_eq!((page.index, page.pages, page.range), (index, pages, range));
        }
        let page = Page::new(usize::MAX, usize::MAX);
        assert_eq!(page.range.end, usize::MAX);
        assert!(page.range.len() <= PAGE_SIZE);
    }

    #[test]
    fn item_deltas_preserve_unchanged_search_text_and_remove_stale_metadata() {
        let mut app = crate::gui::tests::app();
        let item = |id, name: &str| ItemSummary {
            tags: vec![],
            favorite: false,
            id,
            revision: 1,
            name: name.into(),
            username: None,
            kind: ItemKind::Login,
            urls: vec![],
            has_totp: false,
            has_duo: false,
        };
        app.replace_items(vec![item(1, "Alpha"), item(2, "ÉCOLE")]);
        app.items_revision = Some(1);
        app.query = "École".into();
        assert_eq!(&*app.matching_items(), &[1]);
        let unchanged = app.ui.search_text.borrow()[&2].values[0].as_ptr();
        let mut changed = item(1, "Zulu");
        changed.revision = 2;
        assert!(
            app.apply_item_changes(&password_manager::vault::ItemChanges {
                base_revision: 1,
                revision: 2,
                items: vec![changed],
                removed: vec![],
            })
        );
        assert_eq!(
            app.ui.search_text.borrow()[&2].values[0].as_ptr(),
            unchanged
        );
        assert!(!app.ui.search_text.borrow().contains_key(&1));
        assert_eq!(app.items[app.matching_items()[0]].id, 2);
        app.query = "alpha".into();
        assert!(app.matching_items().is_empty());
        app.query = "zulu".into();
        assert_eq!(app.items[app.matching_items()[0]].id, 1);
        assert!(
            app.apply_item_changes(&password_manager::vault::ItemChanges {
                base_revision: 2,
                revision: 3,
                items: vec![],
                removed: vec![2],
            })
        );
        assert!(!app.ui.search_text.borrow().contains_key(&2));
        app.clear_vault();
        assert!(app.ui.search_text.borrow().is_empty());
    }
    #[test]
    fn cached_matches_follow_search_kind_refresh_and_lock() {
        let mut app = crate::gui::tests::app();
        let summary = |name: &str, kind| ItemSummary {
            tags: vec![],
            favorite: false,
            id: 1,
            revision: 1,
            name: name.into(),
            username: None,
            kind,
            urls: vec!["https://école.example".into()],
            has_totp: false,
            has_duo: false,
        };
        app.replace_items(vec![summary("ÉCOLE", ItemKind::Login)]);
        let _ = app.update(Message::Search(" École ".into()));
        assert_eq!(&*app.matching_items(), &[0]);
        let _ = app.update(Message::FilterKind(Some(ItemKind::Identity)));
        assert!(app.matching_items().is_empty());
        let _ = app.update(Message::FilterKind(None));
        assert_eq!(&*app.matching_items(), &[0]);
        app.replace_items(vec![summary("other", ItemKind::Identity)]);
        let _ = app.update(Message::Search("other".into()));
        assert_eq!(&*app.matching_items(), &[0]);
        app.replace_items(vec![summary("different", ItemKind::Identity)]);
        assert!(app.matching_items().is_empty());
        app.clear_vault();
        assert!(app.matching_items().is_empty());
    }
    #[test]
    fn tag_choices_are_deduplicated_sorted_and_follow_item_changes() {
        let mut app = crate::gui::tests::app();
        let item = |id, revision, tags: &[&str]| ItemSummary {
            tags: tags.iter().map(|tag| (*tag).into()).collect(),
            favorite: false,
            id,
            revision,
            name: format!("item {id}"),
            username: None,
            kind: ItemKind::Login,
            urls: vec![],
            has_totp: false,
            has_duo: false,
        };
        app.replace_items(vec![
            item(1, 1, &["work", "Bank"]),
            item(2, 1, &["WORK", "école"]),
        ]);
        app.items_revision = Some(1);
        // First spelling wins; the order ignores case.
        assert_eq!(*app.available_tags(), ["Bank", "work", "école"]);
        assert!(
            app.apply_item_changes(&password_manager::vault::ItemChanges {
                base_revision: 1,
                revision: 2,
                items: vec![item(1, 2, &["Archive"])],
                removed: vec![],
            })
        );
        assert_eq!(*app.available_tags(), ["Archive", "WORK", "école"]);
        app.clear_vault();
        assert!(app.available_tags().is_empty());
    }
    fn luminance(color: Color) -> f32 {
        let channel = |value: f32| {
            if value <= 0.04045 {
                value / 12.92
            } else {
                ((value + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(color.r) + 0.7152 * channel(color.g) + 0.0722 * channel(color.b)
    }
    #[test]
    fn themes_keep_body_and_action_text_readable() {
        let mut app = crate::gui::tests::app();
        for appearance in [
            Appearance::Dark,
            Appearance::Light,
            Appearance::HighContrast,
        ] {
            app.settings.appearance = appearance;
            let theme = app.theme();
            let palette = theme.extended_palette();
            let border = luminance(palette.background.strong.color);
            let panel = luminance(palette.background.weak.color);
            let border_ratio = (border.max(panel) + 0.05) / (border.min(panel) + 0.05);
            assert!(
                border_ratio >= 3.0,
                "{appearance:?}: control boundary contrast {border_ratio}"
            );
            for pair in [
                palette.background.base,
                palette.background.weak,
                palette.background.strong,
                palette.primary.base,
                palette.danger.base,
            ] {
                let a = luminance(pair.color);
                let b = luminance(pair.text);
                let ratio = (a.max(b) + 0.05) / (a.min(b) + 0.05);
                assert!(ratio >= 4.5, "{appearance:?}: text contrast {ratio}");
            }
        }
    }
}
