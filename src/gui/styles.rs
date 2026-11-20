//! Shared button, panel, and label styling, so every desktop view uses one look.
use super::{
    Element, Message, Theme, presentation,
    widgets::{Button, button},
};
use iced::widget::{button as button_style, container, text};

/// Bordered secondary action with a 15-point label.
pub(super) fn action<'a>(label: &'a str, message: Message, enabled: bool) -> Button<'a> {
    button(text(label).size(15))
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
pub(super) fn primary<'a>(label: &'a str, message: Message, enabled: bool) -> Button<'a> {
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

pub(super) fn label(value: &str) -> iced::widget::Text<'_> {
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
