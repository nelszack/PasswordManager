use super::*;
use iced::{Color, theme::Palette};
use password_manager::config::Appearance;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum SettingsSection {
    #[default]
    Appearance,
    Security,
    Passwords,
    Recovery,
    Connection,
}

impl SettingsSection {
    pub const ALL: [Self; 5] = [
        Self::Appearance,
        Self::Security,
        Self::Passwords,
        Self::Recovery,
        Self::Connection,
    ];
    pub fn title(self) -> &'static str {
        match self {
            Self::Appearance => "Appearance",
            Self::Security => "Security",
            Self::Passwords => "Passwords",
            Self::Recovery => "Recovery",
            Self::Connection => "Connection",
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
            115 => "Larger",
            130 => "Largest",
            _ => "Standard",
        };
        write!(f, "{}% · {label}", self.0)
    }
}

pub(super) struct State {
    pub width: f32,
    pub height: f32,
    pub unlock_advanced: bool,
    pub editor_advanced: bool,
    pub editor_authenticators: bool,
    pub editor_show_secret: bool,
    pub generator_advanced: bool,
    pub shortcuts: bool,
    pub settings_section: SettingsSection,
    pub kind: Option<ItemKind>,
    pub notice_error: bool,
    pub confirm_stop: bool,
    pub active_vault: Option<(String, String)>,
    pub undo_trash: Option<(usize, String)>,
    pub vault_name: String,
    pub master_error: Option<&'static str>,
    pub saved_item: Option<SavedItem>,
}

/// Public metadata only, used to identify a confirmed new save without keeping
/// its password or guessing between concurrent additions.
pub(super) struct SavedItem {
    pub name: String,
    pub kind: ItemKind,
    pub previous_ids: Vec<usize>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            width: 1060.0,
            height: 760.0,
            unlock_advanced: false,
            editor_advanced: false,
            editor_authenticators: false,
            editor_show_secret: false,
            generator_advanced: false,
            shortcuts: false,
            settings_section: SettingsSection::default(),
            kind: None,
            notice_error: false,
            confirm_stop: false,
            master_error: None,
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
}

impl App {
    pub(super) fn compact(&self) -> bool {
        self.ui.width < 900.0
    }

    pub(super) fn theme(&self) -> Theme {
        match self.settings.appearance {
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
        f32::from(self.settings.scale.clamp(100, 130)) / 100.0
    }

    pub(super) fn vault_choices(&self) -> Vec<vault_names::Choice> {
        let labels: Vec<_> = self
            .vaults
            .iter()
            .map(|id| self.names.label(id, &self.vaults))
            .collect();
        self.vaults
            .iter()
            .enumerate()
            .map(|(index, id)| {
                let label = &labels[index];
                let label = if labels.iter().filter(|value| *value == label).count() > 1 {
                    format!("{label} · {}", index + 1)
                } else {
                    label.clone()
                };
                vault_names::Choice {
                    id: id.clone(),
                    label,
                }
            })
            .collect()
    }

    pub(super) fn item_matches(&self, item: &ItemSummary) -> bool {
        self.ui.kind.is_none_or(|kind| kind == item.kind)
            && (self.query.trim().is_empty()
                || std::iter::once(item.name.as_str())
                    .chain(item.username.as_deref())
                    .chain(item.urls.iter().map(String::as_str))
                    .any(|value| {
                        value
                            .to_lowercase()
                            .contains(&self.query.trim().to_lowercase())
                    }))
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
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|date| {
            date.with_timezone(&chrono::Local)
                .format("%b %d, %Y · %H:%M")
                .to_string()
        })
        .unwrap_or_else(|_| value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
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
