//! Keyboard access for native controls that Iced 0.14 exposes only to pointers.
//! Pointer handling, layout, styling, and overlays stay with the native widgets.
use super::{Element, Message, Theme};
use iced::{
    Border, Color, Event, Length, Padding, Rectangle, Renderer, Size, Vector,
    advanced::{
        Clipboard, Layout, Shell, Widget, layout, mouse, overlay, renderer,
        widget::{self, Tree, operation::Focusable, tree},
    },
    keyboard::{self, Key, key::Named},
    widget::{button as native_button, checkbox as native_checkbox, pick_list as native_pick_list},
};
use std::{borrow::Borrow, rc::Rc};

pub(super) fn text_input<'a>(
    placeholder: &str,
    value: &str,
) -> iced::widget::TextInput<'a, Message> {
    iced::widget::text_input(placeholder, value).style(|theme: &Theme, status| {
        let mut style = iced::widget::text_input::default(theme, status);
        style.border.radius = 8.0.into();
        style.placeholder =
            super::presentation::blend(theme.palette().background, theme.palette().text, 0.68);
        style
    })
}

/// Keep the scrollbar distinguishable in every appearance, including High contrast.
pub(super) fn scrollable<'a>(
    content: impl Into<Element<'a, Message>>,
) -> iced::widget::Scrollable<'a, Message> {
    iced::widget::scrollable(content).style(|theme: &Theme, status| {
        let mut style = iced::widget::scrollable::default(theme, status);
        let palette = theme.extended_palette();
        let rail = iced::widget::scrollable::Rail {
            background: Some(palette.background.weak.color.into()),
            border: iced::border::rounded(4),
            scroller: iced::widget::scrollable::Scroller {
                background: palette.background.strong.color.into(),
                border: iced::border::rounded(4),
            },
        };
        style.vertical_rail = rail;
        style.horizontal_rail = rail;
        style
    })
}

type KeyHandler<'a> = Box<dyn Fn(&Key) -> Option<Message> + 'a>;

struct Control<'a> {
    content: Element<'a, Message>,
    on_key: Option<KeyHandler<'a>>,
}

struct Focus {
    id: widget::Id,
    focused: bool,
}
impl Default for Focus {
    fn default() -> Self {
        Self {
            id: widget::Id::unique(),
            focused: false,
        }
    }
}
impl Focusable for Focus {
    fn is_focused(&self) -> bool {
        self.focused
    }
    fn focus(&mut self) {
        self.focused = true;
    }
    fn unfocus(&mut self) {
        self.focused = false;
    }
}

impl Widget<Message, Theme, Renderer> for Control<'_> {
    fn tag(&self) -> tree::Tag {
        tree::Tag::of::<Focus>()
    }
    fn state(&self) -> tree::State {
        tree::State::new(Focus::default())
    }
    fn children(&self) -> Vec<Tree> {
        vec![Tree::new(&self.content)]
    }
    fn diff(&self, tree: &mut Tree) {
        tree.diff_children(std::slice::from_ref(&self.content));
    }
    fn size(&self) -> Size<Length> {
        self.content.as_widget().size()
    }
    fn size_hint(&self) -> Size<Length> {
        self.content.as_widget().size_hint()
    }
    fn layout(
        &mut self,
        tree: &mut Tree,
        renderer: &Renderer,
        limits: &layout::Limits,
    ) -> layout::Node {
        self.content
            .as_widget_mut()
            .layout(&mut tree.children[0], renderer, limits)
    }
    fn operate(
        &mut self,
        tree: &mut Tree,
        layout: Layout<'_>,
        renderer: &Renderer,
        operation: &mut dyn widget::Operation,
    ) {
        let state = tree.state.downcast_mut::<Focus>();
        if self.on_key.is_some() {
            let id = state.id.clone();
            operation.focusable(Some(&id), layout.bounds(), state);
        } else {
            state.focused = false;
        }
        self.content
            .as_widget_mut()
            .operate(&mut tree.children[0], layout, renderer, operation);
    }
    fn update(
        &mut self,
        tree: &mut Tree,
        event: &Event,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        renderer: &Renderer,
        clipboard: &mut dyn Clipboard,
        shell: &mut Shell<'_, Message>,
        viewport: &Rectangle,
    ) {
        let state = tree.state.downcast_mut::<Focus>();
        if let Event::Mouse(mouse::Event::ButtonPressed(mouse::Button::Left)) = event {
            let focused = self.on_key.is_some()
                && !shell.is_event_captured()
                && cursor.is_over(layout.bounds());
            if state.focused != focused {
                state.focused = focused;
                shell.request_redraw();
            }
        }
        if !shell.is_event_captured()
            && state.focused
            && let Some(on_key) = &self.on_key
            && let Event::Keyboard(keyboard::Event::KeyPressed {
                key,
                modifiers,
                repeat: false,
                ..
            }) = event
            && !modifiers.command()
            && !modifiers.alt()
            && let Some(message) = on_key(key)
        {
            shell.publish(message);
            shell.capture_event();
            return;
        }
        self.content.as_widget_mut().update(
            &mut tree.children[0],
            event,
            layout,
            cursor,
            renderer,
            clipboard,
            shell,
            viewport,
        );
    }
    fn draw(
        &self,
        tree: &Tree,
        renderer: &mut Renderer,
        theme: &Theme,
        style: &renderer::Style,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
    ) {
        self.content.as_widget().draw(
            &tree.children[0],
            renderer,
            theme,
            style,
            layout,
            cursor,
            viewport,
        );
        if self.on_key.is_some() && tree.state.downcast_ref::<Focus>().focused {
            use iced::advanced::Renderer as _;
            renderer.fill_quad(
                renderer::Quad {
                    bounds: layout.bounds().shrink(2.0),
                    border: Border {
                        color: theme.palette().text,
                        width: 2.0,
                        radius: 6.0.into(),
                    },
                    ..Default::default()
                },
                Color::TRANSPARENT,
            );
        }
    }
    fn mouse_interaction(
        &self,
        tree: &Tree,
        layout: Layout<'_>,
        cursor: mouse::Cursor,
        viewport: &Rectangle,
        renderer: &Renderer,
    ) -> mouse::Interaction {
        self.content.as_widget().mouse_interaction(
            &tree.children[0],
            layout,
            cursor,
            viewport,
            renderer,
        )
    }
    fn overlay<'b>(
        &'b mut self,
        tree: &'b mut Tree,
        layout: Layout<'b>,
        renderer: &Renderer,
        viewport: &Rectangle,
        translation: Vector,
    ) -> Option<overlay::Element<'b, Message, Theme, Renderer>> {
        self.content.as_widget_mut().overlay(
            &mut tree.children[0],
            layout,
            renderer,
            viewport,
            translation,
        )
    }
}

fn activate(key: &Key) -> bool {
    matches!(key, Key::Named(Named::Enter | Named::Space))
        || matches!(key, Key::Character(c) if c == " ")
}

pub(super) struct Button<'a> {
    inner: iced::widget::Button<'a, Message>,
    message: Option<Message>,
}
pub(super) fn button<'a>(content: impl Into<Element<'a, Message>>) -> Button<'a> {
    Button {
        inner: native_button(content).style(|theme, status| {
            let mut style = native_button::primary(theme, status);
            style.border.radius = 8.0.into();
            style
        }),
        message: None,
    }
}
impl<'a> Button<'a> {
    pub fn padding(mut self, padding: impl Into<Padding>) -> Self {
        self.inner = self.inner.padding(padding);
        self
    }
    pub fn width(mut self, width: impl Into<Length>) -> Self {
        self.inner = self.inner.width(width);
        self
    }
    pub fn style(
        mut self,
        style: impl Fn(&Theme, native_button::Status) -> native_button::Style + 'a,
    ) -> Self {
        self.inner = self.inner.style(move |theme, status| {
            let mut result = style(theme, status);
            result.border.radius = 8.0.into();
            result
        });
        self
    }
    pub fn on_press(self, message: Message) -> Self {
        self.on_press_maybe(Some(message))
    }
    pub fn on_press_maybe(mut self, message: Option<Message>) -> Self {
        self.inner = self.inner.on_press_maybe(message.clone());
        self.message = message;
        self
    }
}
impl<'a> From<Button<'a>> for Element<'a, Message> {
    fn from(button: Button<'a>) -> Self {
        Element::new(Control {
            content: button.inner.into(),
            on_key: button.message.map(|message| {
                Box::new(move |key: &Key| activate(key).then(|| message.clone())) as KeyHandler<'a>
            }),
        })
    }
}

pub(super) struct Checkbox<'a> {
    inner: iced::widget::Checkbox<'a, Message>,
    checked: bool,
    on_key: Option<KeyHandler<'a>>,
}
pub(super) fn checkbox<'a>(checked: bool) -> Checkbox<'a> {
    Checkbox {
        inner: native_checkbox(checked).size(24).spacing(12),
        checked,
        on_key: None,
    }
}
impl<'a> Checkbox<'a> {
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.inner = self.inner.label(label.into());
        self
    }
    pub fn on_toggle(self, toggle: impl Fn(bool) -> Message + 'a) -> Self {
        self.on_toggle_maybe(Some(toggle))
    }
    pub fn on_toggle_maybe(mut self, toggle: Option<impl Fn(bool) -> Message + 'a>) -> Self {
        if let Some(toggle) = toggle {
            let toggle = Rc::new(toggle);
            let pointer = toggle.clone();
            let checked = self.checked;
            self.inner = self.inner.on_toggle(move |value| pointer(value));
            self.on_key = Some(Box::new(move |key| activate(key).then(|| toggle(!checked))));
        }
        self
    }
}
impl<'a> From<Checkbox<'a>> for Element<'a, Message> {
    fn from(checkbox: Checkbox<'a>) -> Self {
        Element::new(Control {
            content: checkbox.inner.into(),
            on_key: checkbox.on_key,
        })
    }
}

pub(super) struct PickList<'a, T: ToString + PartialEq + Clone + 'a> {
    inner: iced::widget::PickList<'a, T, Vec<T>, T, Message>,
    on_key: KeyHandler<'a>,
}
pub(super) fn pick_list<'a, T: ToString + PartialEq + Clone + 'a>(
    options: impl AsRef<[T]>,
    selected: Option<impl Borrow<T>>,
    on_selected: impl Fn(T) -> Message + 'a,
) -> PickList<'a, T> {
    let options = options.as_ref().to_vec();
    let selected = selected.map(|value| value.borrow().clone());
    let current = selected
        .as_ref()
        .and_then(|selected| options.iter().position(|value| value == selected));
    let callback = Rc::new(on_selected);
    let pointer = callback.clone();
    let inner = native_pick_list(options.clone(), selected, move |value| pointer(value)).style(
        |theme, status| {
            let mut style = native_pick_list::default(theme, status);
            style.border.radius = 8.0.into();
            style
        },
    );
    PickList {
        inner,
        on_key: Box::new(move |key| {
            let index = selection_index(key, current, options.len())?;
            Some(callback(options[index].clone()))
        }),
    }
}
fn selection_index(key: &Key, current: Option<usize>, count: usize) -> Option<usize> {
    if count == 0 {
        return None;
    }
    match key {
        Key::Named(Named::ArrowDown | Named::ArrowRight) => {
            Some(current.map_or(0, |index| (index + 1).min(count - 1)))
        }
        Key::Named(Named::ArrowUp | Named::ArrowLeft) => {
            Some(current.map_or(count - 1, |index| index.saturating_sub(1)))
        }
        Key::Named(Named::Home) => Some(0),
        Key::Named(Named::End) => Some(count - 1),
        _ => None,
    }
}
impl<'a, T: ToString + PartialEq + Clone + 'a> PickList<'a, T> {
    pub fn padding(mut self, padding: impl Into<Padding>) -> Self {
        self.inner = self.inner.padding(padding);
        self
    }
    pub fn width(mut self, width: impl Into<Length>) -> Self {
        self.inner = self.inner.width(width);
        self
    }
    pub fn placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.inner = self.inner.placeholder(placeholder);
        self
    }
}
impl<'a, T: ToString + PartialEq + Clone + 'a> From<PickList<'a, T>> for Element<'a, Message> {
    fn from(picker: PickList<'a, T>) -> Self {
        Element::new(Control {
            content: picker.inner.into(),
            on_key: Some(picker.on_key),
        })
    }
}

/// Keep keyboard focus visible through nested form and page scroll areas.
pub(super) fn ensure_focus_visible() -> iced::Task<Message> {
    use widget::operation::{Operation, Outcome, scrollable::Scrollable};
    #[derive(Clone)]
    struct Scroll {
        id: widget::Id,
        bounds: Rectangle,
        translation: Vector,
    }
    #[derive(Default)]
    struct Find {
        pending: Option<Scroll>,
        ancestors: Vec<Scroll>,
        result: Vec<(widget::Id, f32)>,
    }
    impl Operation<Message> for Find {
        fn scrollable(
            &mut self,
            id: Option<&widget::Id>,
            bounds: Rectangle,
            _content: Rectangle,
            translation: Vector,
            _state: &mut dyn Scrollable,
        ) {
            self.pending = id.map(|id| Scroll {
                id: id.clone(),
                bounds,
                translation,
            });
        }
        fn traverse(&mut self, visit: &mut dyn FnMut(&mut dyn Operation<Message>)) {
            let added = self.pending.take();
            if let Some(scroll) = &added {
                self.ancestors.push(scroll.clone());
            }
            visit(self);
            if added.is_some() {
                self.ancestors.pop();
            }
        }
        fn focusable(
            &mut self,
            _id: Option<&widget::Id>,
            bounds: Rectangle,
            state: &mut dyn Focusable,
        ) {
            if !state.is_focused() {
                return;
            }
            let mut top = bounds.y;
            let mut height = bounds.height;
            for scroll in self.ancestors.iter().rev() {
                top -= scroll.translation.y;
                let delta = focus_offset(top, height, scroll.bounds);
                if delta.abs() > 0.5 {
                    self.result.push((scroll.id.clone(), delta));
                }
                top -= delta;
                height = height.min(scroll.bounds.height);
            }
        }
        fn finish(&self) -> Outcome<Message> {
            if self.result.is_empty() {
                Outcome::None
            } else {
                Outcome::Some(Message::ScrollFocus(self.result.clone()))
            }
        }
    }
    widget::operate(Find::default())
}

fn focus_offset(top: f32, height: f32, viewport: Rectangle) -> f32 {
    if top < viewport.y {
        top - viewport.y - 8.0
    } else if top + height > viewport.y + viewport.height {
        top + height - viewport.y - viewport.height + 8.0
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn focus_scrolling_brings_offscreen_controls_back_into_view() {
        let viewport = Rectangle {
            x: 0.0,
            y: 100.0,
            width: 300.0,
            height: 200.0,
        };
        assert_eq!(focus_offset(120.0, 40.0, viewport), 0.0);
        for (top, height) in [(80.0, 40.0), (290.0, 40.0)] {
            let adjusted = top - focus_offset(top, height, viewport);
            assert!(adjusted >= viewport.y && adjusted + height <= viewport.y + viewport.height);
        }
    }

    fn press(
        control: &mut Element<'_, Message>,
        focused: bool,
        key: Key,
        repeat: bool,
        modifiers: keyboard::Modifiers,
    ) -> Vec<Message> {
        let renderer = Renderer::new(iced::Font::DEFAULT, iced::Pixels(16.0));
        let mut tree = Tree::new(&*control);
        let node = control.as_widget_mut().layout(
            &mut tree,
            &renderer,
            &layout::Limits::new(Size::ZERO, Size::new(300.0, 100.0)),
        );
        tree.state.downcast_mut::<Focus>().focused = focused;
        let event = Event::Keyboard(keyboard::Event::KeyPressed {
            modified_key: key.clone(),
            key,
            physical_key: keyboard::key::Physical::Unidentified(
                keyboard::key::NativeCode::Unidentified,
            ),
            location: keyboard::Location::Standard,
            modifiers,
            text: None,
            repeat,
        });
        let mut messages = vec![];
        control.as_widget_mut().update(
            &mut tree,
            &event,
            Layout::new(&node),
            mouse::Cursor::Unavailable,
            &renderer,
            &mut iced::advanced::clipboard::Null,
            &mut Shell::new(&mut messages),
            &Rectangle::with_size(Size::new(300.0, 100.0)),
        );
        messages
    }

    #[test]
    fn keyboard_activation_requires_focus_enabled_control_and_unmodified_press() {
        let mut control: Element<'_, Message> = button("Save").on_press(Message::Save).into();
        assert!(
            press(
                &mut control,
                false,
                Key::Named(Named::Enter),
                false,
                keyboard::Modifiers::empty()
            )
            .is_empty()
        );
        assert!(matches!(
            press(
                &mut control,
                true,
                Key::Named(Named::Enter),
                false,
                keyboard::Modifiers::empty()
            )
            .as_slice(),
            [Message::Save]
        ));
        assert!(
            press(
                &mut control,
                true,
                Key::Named(Named::Enter),
                true,
                keyboard::Modifiers::empty()
            )
            .is_empty()
        );
        assert!(
            press(
                &mut control,
                true,
                Key::Named(Named::Space),
                false,
                keyboard::Modifiers::CTRL
            )
            .is_empty()
        );
        let mut disabled: Element<'_, Message> = button("Save").into();
        assert!(
            press(
                &mut disabled,
                true,
                Key::Named(Named::Enter),
                false,
                keyboard::Modifiers::empty()
            )
            .is_empty()
        );
    }

    #[test]
    fn checkbox_and_picker_publish_changes_from_the_keyboard() {
        let mut toggle: Element<'_, Message> = checkbox(false)
            .label("Passphrase")
            .on_toggle(Message::Passphrase)
            .into();
        assert!(matches!(
            press(
                &mut toggle,
                true,
                Key::Named(Named::Space),
                false,
                keyboard::Modifiers::empty()
            )
            .as_slice(),
            [Message::Passphrase(true)]
        ));
        let mut picker: Element<'_, Message> =
            pick_list([100_u16, 115, 130], Some(100_u16), Message::InterfaceScale).into();
        assert!(matches!(
            press(
                &mut picker,
                true,
                Key::Named(Named::ArrowDown),
                false,
                keyboard::Modifiers::empty()
            )
            .as_slice(),
            [Message::InterfaceScale(115)]
        ));
    }

    #[test]
    fn keyboard_selection_stays_in_bounds_and_handles_empty_lists() {
        assert_eq!(
            selection_index(&Key::Named(Named::ArrowDown), None, 0),
            None
        );
        assert_eq!(
            selection_index(&Key::Named(Named::ArrowDown), None, 3),
            Some(0)
        );
        assert_eq!(
            selection_index(&Key::Named(Named::ArrowUp), None, 3),
            Some(2)
        );
        assert_eq!(
            selection_index(&Key::Named(Named::ArrowDown), Some(2), 3),
            Some(2)
        );
        assert_eq!(
            selection_index(&Key::Named(Named::ArrowUp), Some(0), 3),
            Some(0)
        );
        assert_eq!(
            selection_index(&Key::Named(Named::Home), Some(2), 3),
            Some(0)
        );
        assert_eq!(
            selection_index(&Key::Named(Named::End), Some(0), 3),
            Some(2)
        );
    }
}
