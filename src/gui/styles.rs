//! Shared button, panel, and label styling, so every desktop view uses one look.
use super::{
    Element, Message, Theme, presentation,
    widgets::{Button, button},
};
use iced::widget::{button as button_style, container, text};

/// The bundled Material Icons subset (assets/material-icons.ttf, Apache 2.0).
pub(super) const ICON_FONT: iced::Font = iced::Font::with_name("Material Icons");

/// One icon glyph from [`super::icon_chars`], sized to sit beside 15-point text.
pub(super) fn icon<'a>(glyph: char) -> iced::widget::Text<'a> {
    text(glyph.to_string())
        .font(ICON_FONT)
        .size(17)
        .line_height(1.0)
}

/// The icon for a common action, chosen from its label so every surface of the
/// app uses the same symbol for the same task.
fn action_icon(label: &str) -> Option<char> {
    use super::icon_chars as i;
    let starts = |prefixes: &[&str]| prefixes.iter().any(|p| label.starts_with(p));
    // More specific labels first: "Create a backup" is a backup, not a new item.
    Some(if starts(&["Copy"]) {
        i::CONTENT_COPY
    } else if starts(&[
        "Create a backup",
        "Create complete",
        "Back up",
        "Encrypted backup",
    ]) {
        i::BACKUP
    } else if starts(&["Check vault health", "Vault health", "Run health check"]) {
        i::HEALTH_AND_SAFETY
    } else if starts(&["Reveal", "Show "]) {
        i::VISIBILITY
    } else if starts(&["Hide"]) {
        i::VISIBILITY_OFF
    } else if starts(&["Edit"]) {
        i::EDIT
    } else if starts(&["Permanently delete", "Delete", "Empty trash", "Purge"]) {
        i::DELETE_FOREVER
    } else if starts(&["Move to trash", "Move ", "Remove"]) {
        i::DELETE
    } else if starts(&["Lock"]) {
        i::LOCK
    } else if starts(&["Add", "New ", "Create"]) {
        i::ADD
    } else if starts(&["Search", "Advanced search"]) {
        i::SEARCH
    } else if starts(&["Refresh", "Check again", "Find existing"]) {
        i::REFRESH
    } else if starts(&["Generate", "Suggest"]) {
        i::AUTORENEW
    } else if starts(&["Open website", "Open the"]) {
        i::OPEN_IN_NEW
    } else if starts(&["Restore", "Undo"]) {
        i::RESTORE
    } else if starts(&["Download", "Export"]) {
        i::FILE_DOWNLOAD
    } else if starts(&["Import", "Upload"]) {
        i::FILE_UPLOAD
    } else if starts(&["Sync", "Turn on sync", "Turn off sync"]) {
        i::SYNC
    } else if starts(&["Save"]) {
        i::CHECK
    } else if starts(&["Help"]) {
        i::HELP_OUTLINE
    } else if starts(&["Back"]) {
        i::ARROW_BACK
    } else if starts(&["Cancel", "Close", "Dismiss"]) {
        i::CLOSE
    } else if starts(&["Password history", "History"]) {
        i::HISTORY
    } else if starts(&["Settings", "Open settings"]) {
        i::SETTINGS
    } else {
        return None;
    })
}

/// A bordered action showing [`icon`] before its label; screen readers hear the label.
pub(super) fn icon_button<'a>(
    glyph: char,
    label: impl Into<String>,
    message: Message,
    enabled: bool,
) -> Button<'a> {
    let label = label.into();
    button(
        iced::widget::row![icon(glyph), text(label.clone()).size(15)]
            .spacing(7)
            .align_y(iced::Alignment::Center),
    )
    .accessible_name(label)
    .padding([11, 14])
    .style(quiet_button)
    .on_press_maybe(enabled.then_some(message))
}

/// The same bordered action with text only (disclosures, where an icon would mislead).
pub(super) fn text_action<'a>(
    label: impl text::IntoFragment<'a>,
    message: Message,
    enabled: bool,
) -> Button<'a> {
    button(text(label).size(15))
        .padding([11, 14])
        .style(quiet_button)
        .on_press_maybe(enabled.then_some(message))
}

/// Bordered secondary action with a 15-point label and, for common tasks, an icon.
pub(super) fn action<'a>(
    label: impl text::IntoFragment<'a>,
    message: Message,
    enabled: bool,
) -> Button<'a> {
    let label = label.into_fragment();
    let content: Element<'a, Message> = match action_icon(&label) {
        // The icon is decoration: screen readers hear only the label.
        Some(glyph) => {
            let name = label.to_string();
            return button(
                iced::widget::row![icon(glyph), text(label).size(15)]
                    .spacing(7)
                    .align_y(iced::Alignment::Center),
            )
            .accessible_name(name)
            .padding([11, 14])
            .style(quiet_button)
            .on_press_maybe(enabled.then_some(message));
        }
        None => text(label).size(15).into(),
    };
    button(content)
        .padding([11, 14])
        .style(quiet_button)
        .on_press_maybe(enabled.then_some(message))
}

pub(super) fn quiet_button(theme: &Theme, status: button_style::Status) -> button_style::Style {
    let palette = theme.extended_palette();
    let mut style = button_style::text(theme, status);
    style.border = iced::Border {
        color: palette.background.strong.color,
        width: 1.0,
        radius: 8.0.into(),
    };
    if matches!(
        status,
        button_style::Status::Hovered | button_style::Status::Pressed
    ) {
        style.background = Some(palette.background.weak.color.into());
        style.border.color = palette.primary.base.color;
    }
    style
}

pub(super) fn quiet_danger(theme: &Theme, status: button_style::Status) -> button_style::Style {
    let mut style = quiet_button(theme, status);
    if status != button_style::Status::Disabled {
        style.text_color = theme.extended_palette().danger.base.color;
        style.border.color = style.text_color;
    }
    style
}

/// Filled primary action with the same shape and label size as [`action`].
pub(super) fn primary<'a>(
    label: impl text::IntoFragment<'a>,
    message: Message,
    enabled: bool,
) -> Button<'a> {
    // `Button::style` rounds every variant to the shared 8 px radius.
    action(label, message, enabled).style(button_style::primary)
}

/// Navigation and section tabs: selected tabs are filled and outlined so they
/// stay distinct in every theme, including high contrast.
pub(super) fn tab_style(
    selected: bool,
) -> impl Fn(&Theme, button_style::Status) -> button_style::Style {
    move |theme, status| {
        let palette = theme.extended_palette();
        let mut style = button_style::text(theme, status);
        style.border = iced::Border {
            color: iced::Color::TRANSPARENT,
            width: 2.0,
            radius: 8.0.into(),
        };
        if selected {
            style.background = Some(palette.primary.weak.color.into());
            style.text_color = palette.primary.weak.text;
            style.border.color = palette.primary.base.color;
        } else {
            style.text_color = palette.background.base.text;
            if matches!(
                status,
                button_style::Status::Hovered | button_style::Status::Pressed
            ) {
                style.background = Some(palette.background.weak.color.into());
            }
        }
        style
    }
}

/// A hover hint, used to show an action's keyboard shortcut.
pub(super) fn tip<'a>(
    content: impl Into<Element<'a, Message>>,
    hint: String,
) -> Element<'a, Message> {
    iced::widget::tooltip(
        content,
        container(text(hint).size(13))
            .padding([4, 8])
            .style(container::rounded_box),
        iced::widget::tooltip::Position::Bottom,
    )
    .gap(4)
    .into()
}

/// "Ctrl" or "Cmd", for shortcut hints.
pub(super) fn command_key() -> &'static str {
    if cfg!(target_os = "macos") {
        "Cmd"
    } else {
        "Ctrl"
    }
}

pub(super) fn label<'a>(value: impl text::IntoFragment<'a>) -> iced::widget::Text<'a> {
    text(value).size(14)
}

pub(super) fn error<'a>(value: impl Into<String>) -> iced::widget::Text<'a> {
    text(value.into()).size(14).style(text::danger)
}

pub(super) fn panel<'a>(
    content: impl Into<Element<'a, Message>>,
) -> iced::widget::Container<'a, Message> {
    container(content).padding(16).style(|theme: &Theme| {
        let palette = theme.extended_palette();
        container::Style {
            background: Some(palette.background.weak.color.into()),
            text_color: Some(palette.background.weak.text),
            border: iced::Border {
                color: presentation::blend(
                    palette.background.base.color,
                    palette.background.base.text,
                    0.15,
                ),
                width: 1.0,
                radius: 12.0.into(),
            },
            ..Default::default()
        }
    })
}
