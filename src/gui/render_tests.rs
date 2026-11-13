//! Exercise the real widget layout and software renderer without a desktop or vault.
use super::*;
use iced::{
    Rectangle, Size,
    advanced::{
        layout, mouse, renderer,
        widget::{self, operation},
    },
};
use std::io::Write;

#[derive(Default)]
struct Controls(Vec<(String, Rectangle)>, Vec<String>);
impl widget::Operation for Controls {
    fn text(&mut self, _: Option<&widget::Id>, _: Rectangle, text: &str) {
        self.1.push(text.to_owned());
    }
    fn traverse(&mut self, operate: &mut dyn FnMut(&mut dyn widget::Operation)) {
        operate(self);
    }
    fn focusable(
        &mut self,
        id: Option<&widget::Id>,
        bounds: Rectangle,
        _: &mut dyn operation::Focusable,
    ) {
        self.0.push((format!("{id:?}"), bounds));
    }
}

fn render(app: &App, name: &str, width: u32, height: u32, scale: f32) -> Controls {
    use renderer::{Headless, Renderer as _};
    let size = Size::new(width as f32 / scale, height as f32 / scale);
    let viewport = Rectangle::with_size(size);
    let theme = app.theme();
    let mut renderer = iced::Renderer::new(iced::Font::DEFAULT, iced::Pixels(16.0));
    renderer.reset(viewport);
    let mut element = app.view();
    let mut tree = widget::Tree::new(&element);
    let node = element.as_widget_mut().layout(
        &mut tree,
        &renderer,
        &layout::Limits::new(Size::ZERO, size),
    );
    let mut controls = Controls::default();
    element.as_widget_mut().operate(
        &mut tree,
        layout::Layout::new(&node),
        &renderer,
        &mut controls,
    );
    let mut messages = Vec::new();
    element.as_widget_mut().update(
        &mut tree,
        &iced::Event::Window(iced::window::Event::RedrawRequested(Instant::now())),
        layout::Layout::new(&node),
        mouse::Cursor::Unavailable,
        &renderer,
        &mut iced::advanced::clipboard::Null,
        &mut iced::advanced::Shell::new(&mut messages),
        &viewport,
    );
    element.as_widget().draw(
        &tree,
        &mut renderer,
        &theme,
        &renderer::Style {
            text_color: theme.palette().text,
        },
        layout::Layout::new(&node),
        mouse::Cursor::Unavailable,
        &viewport,
    );
    let pixels = Headless::screenshot(
        &mut renderer,
        Size::new(width, height),
        scale,
        theme.palette().background,
    );
    assert_eq!(pixels.len(), width as usize * height as usize * 4);
    if let Some(dir) = std::env::var_os("PM_GUI_REVIEW_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut file = std::fs::File::create(
            dir.join(format!("{name}-{width}-{}.ppm", (scale * 100.0) as u16)),
        )
        .unwrap();
        write!(file, "P6\n{width} {height}\n255\n").unwrap();
        let rgb: Vec<_> = pixels
            .as_chunks::<4>()
            .0
            .iter()
            .flat_map(|p| p[..3].iter().copied())
            .collect();
        file.write_all(&rgb).unwrap();
    }
    let overflow: Vec<_> = controls
        .0
        .iter()
        .filter(|(_, r)| r.width < 1.0 || r.x < -1.0 || r.x + r.width > size.width + 1.0)
        .collect();
    assert!(
        overflow.is_empty(),
        "{name} at {width} / {scale}: horizontal control overflow {overflow:?}"
    );
    controls
}

fn accessibility_tree(app: &App, focus: Option<&str>) -> iced_winit::a11y::A11yTree {
    use renderer::Renderer as _;
    let mut renderer = iced::Renderer::new(iced::Font::DEFAULT, iced::Pixels(16.0));
    let size = Size::new(1060.0, 760.0);
    renderer.reset(Rectangle::with_size(size));
    let mut element = app.view();
    let mut tree = widget::Tree::new(&element);
    let node = element.as_widget_mut().layout(
        &mut tree,
        &renderer,
        &layout::Limits::new(Size::ZERO, size),
    );
    if let Some(id) = focus {
        let mut focus = operation::focusable::focus(id.to_owned().into());
        element.as_widget_mut().operate(
            &mut tree,
            layout::Layout::new(&node),
            &renderer,
            &mut focus,
        );
    }
    let mut builder = iced_winit::a11y::TreeBuilder::new("Password Manager");
    element.as_widget_mut().operate(
        &mut tree,
        layout::Layout::new(&node),
        &renderer,
        &mut builder,
    );
    builder.build()
}

#[test]
fn accessibility_tree_keeps_button_labels_focus_and_passwords_protected() {
    let mut app = tests::app();
    app.connection.running = true;
    app.request_state = RequestState::Idle;
    app.connection.creating = true;
    app.connection.master = "synthetic-native-protected-value".into();
    let accessible = accessibility_tree(&app, Some("master-password"));
    assert!(!format!("{:?}", accessible.update).contains(app.connection.master.expose()));
    let protected: Vec<_> = accessible
        .update
        .nodes
        .iter()
        .filter(|(_, node)| format!("{:?}", node.role()) == "PasswordInput")
        .collect();
    assert!(!protected.is_empty());
    assert!(protected.iter().all(|(_, node)| node.value().is_none()));
    assert!(
        protected
            .iter()
            .any(|(id, _)| *id == accessible.update.focus)
    );
    // The button's visible label must be its descendant, not a sibling orphaned
    // by the application's keyboard wrapper.
    let settings = accessible
        .update
        .nodes
        .iter()
        .find(|(_, node)| node.value() == Some("Settings"))
        .unwrap()
        .0;
    assert!(
        accessible
            .update
            .nodes
            .iter()
            .any(|(_, node)| format!("{:?}", node.role()) == "Button"
                && node.children().contains(&settings))
    );
}

#[test]
fn accessible_names_feedback_and_selection_follow_the_visible_form() {
    let mut app = tests::app();
    app.connection.running = true;
    app.request_state = RequestState::Idle;
    app.tab = Tab::Generator;
    app.notice = "Synthetic item saved".into();
    let tree = accessibility_tree(&app, None);
    assert!(
        tree.update
            .nodes
            .iter()
            .any(|(_, node)| node.label() == Some("Password length (1–255)"))
    );
    assert!(
        tree.update
            .nodes
            .iter()
            .any(|(_, node)| node.label() == Some("Synthetic item saved")
                && format!("{:?}", node.live()).contains("Polite"))
    );
    let generator_label = tree
        .update
        .nodes
        .iter()
        .find(|(_, node)| node.value() == Some("Generator"))
        .unwrap()
        .0;
    assert!(
        tree.update
            .nodes
            .iter()
            .any(|(_, node)| node.children().contains(&generator_label)
                && node.is_selected() == Some(true))
    );
    app.generation.passphrase = true;
    let tree = accessibility_tree(&app, None);
    for label in ["Number of words (1–255)", "Word separator"] {
        assert!(
            tree.update
                .nodes
                .iter()
                .any(|(_, node)| node.label() == Some(label)),
            "missing accessible name {label}"
        );
    }
    app.tab = Tab::Settings;
    app.ui.settings_section = presentation::SettingsSection::Passwords;
    let tree = accessibility_tree(&app, None);
    assert!(
        tree.update
            .nodes
            .iter()
            .any(|(_, node)| node.label() == Some("Default password length (1–255)"))
    );
}

#[test]
fn ordinary_inputs_expose_text_runs_and_caret_without_exposing_passwords() {
    let mut app = tests::app();
    app.connection.running = true;
    app.request_state = RequestState::Idle;
    app.connection.creating = true;
    app.ui.vault_name = "Café 👩🏽‍💻".into();
    let tree = accessibility_tree(&app, None);
    let input = &tree
        .update
        .nodes
        .iter()
        .find(|(_, node)| node.label() == Some("Vault name"))
        .unwrap()
        .1;
    let selection = input.text_selection().expect("ordinary input has a caret");
    let run = &tree
        .update
        .nodes
        .iter()
        .find(|(id, _)| *id == selection.focus.node)
        .unwrap()
        .1;
    assert!(input.children().contains(&selection.focus.node));
    assert_eq!(run.value(), Some(app.ui.vault_name.as_str()));
    assert_eq!(run.character_lengths().len(), 6);
    assert_eq!(
        run.character_lengths()
            .iter()
            .map(|length| usize::from(*length))
            .sum::<usize>(),
        app.ui.vault_name.len()
    );
    for (_, node) in &tree.update.nodes {
        if format!("{:?}", node.role()) == "PasswordInput" {
            assert!(node.children().is_empty());
            assert!(node.text_selection().is_none());
        }
    }
}

#[test]
fn multiline_notes_expose_readable_text_and_selection() {
    let mut app = tests::app();
    app.connection.running = true;
    app.request_state = RequestState::Idle;
    app.connection.session = Some("synthetic-session".into());
    let mut notes = text_editor::Content::with_text("first\ncafé 👩🏽‍💻");
    notes.move_to(text_editor::Cursor {
        position: text_editor::Position { line: 1, column: 6 },
        selection: Some(text_editor::Position { line: 0, column: 1 }),
    });
    app.editor = Editor::new(Draft {
        notes,
        ..Default::default()
    });
    let tree = accessibility_tree(&app, None);
    let (id, editor) = tree
        .update
        .nodes
        .iter()
        .find(|(_, node)| node.label() == Some("Private notes"))
        .unwrap();
    let selection = editor
        .text_selection()
        .expect("multiline editor exposes its caret");
    assert_eq!(selection.anchor.character_index, 1);
    assert_eq!(selection.focus.character_index, 5);
    assert_eq!(tree.text_run_offsets[&selection.focus.node].0, 6);
    let run = &tree
        .update
        .nodes
        .iter()
        .find(|(id, _)| *id == selection.focus.node)
        .unwrap()
        .1;
    assert_eq!(run.value(), Some("café 👩🏽‍💻"));
    assert!(tree.node_map[id].0.is_some());
}

#[test]
fn rendered_screens_fit_supported_windows() {
    for (width, scale) in [(480, 1.3), (760, 1.0), (1060, 1.0), (1440, 1.3)] {
        let mut app = tests::app();
        app.ui.width = width as f32 / scale;
        app.ui.height = 800.0 / scale;
        app.connection.running = true;
        app.request_state = RequestState::Idle;
        app.notice.clear();
        render(&app, "onboarding", width, 800, scale);
        app.connection.creating = true;
        render(&app, "create", width, 800, scale);
        app.connection.creating = false;
        app.connection.session = Some("synthetic-session".into());
        app.items = (1..=3)
            .map(|id| ItemSummary {
                id,
                revision: 1,
                name: format!("Example account {id}"),
                username: Some("alice@example.test".into()),
                kind: ItemKind::Login,
                urls: vec!["https://example.test".into()],
                has_totp: false,
                has_duo: false,
            })
            .collect();
        render(&app, "items", width, 800, scale);
        app.editor = Editor::new(Draft {
            name: "Example account".into(),
            ..Default::default()
        });
        render(&app, "editor", width, 800, scale);
        app.tab = Tab::Generator;
        render(&app, "generator", width, 800, scale);
        app.tab = Tab::Settings;
        app.cloud.vaults = vec!["a".repeat(32)];
        app.cloud.vault = app.cloud.vaults.first().cloned();
        app.cloud.review = Some(password_manager::cloud::ConflictReview {
            token: "synthetic-review".into(),
            items: vec![password_manager::cloud::ConflictItem {
                id: 1,
                local: "Personal email · alice@example.test · Active".into(),
                remote: "Personal email · alice@example.test · Deleted".into(),
                fields: vec![password_manager::cloud::ConflictField {
                    field: "password".into(),
                    local: "Protected value differs".into(),
                    remote: "Protected value differs".into(),
                }],
            }],
        });
        for section in presentation::SettingsSection::ALL {
            app.ui.settings_section = section;
            render(&app, &format!("settings-{section}"), width, 800, scale);
        }
        app.tab = Tab::Tools;
        render(&app, "tools", width, 800, scale);
        app.workspace.section = workflows::Section::Utilities;
        render(&app, "cli-utilities", width, 800, scale);
        app.connection.session = None;
        render(&app, "cli-utilities-locked", width, 800, scale);
    }
}

#[test]
fn rendered_edge_cases_fit_minimum_windows_and_all_themes() {
    use password_manager::config::Appearance;
    for appearance in [
        Appearance::Light,
        Appearance::Dark,
        Appearance::HighContrast,
    ] {
        let mut app = tests::app();
        app.request_state = RequestState::Idle;
        app.notice.clear();
        app.connection.running = true;
        app.connection.session = Some("synthetic-session".into());
        app.ui.width = 480.0 / 1.3;
        app.ui.height = 480.0 / 1.3;
        app.settings.appearance = appearance;
        let prefix = format!("edge-{appearance:?}");
        for kind in model::KINDS {
            app.editor = Editor::new(Draft {
                name: "Long synthetic item name for review ".repeat(3),
                kind,
                dirty: true,
                urls: vec![format!("https://example.test/{}", "long-path/".repeat(12))],
                ..Default::default()
            });
            app.ui.editor_advanced = true;
            render(&app, &format!("{prefix}-{kind}"), 480, 480, 1.3);
        }
        app.recovery = Recovery::AwaitingOutcome("synthetic-operation".into());
        app.warning =
            Some("Storage warning: keep your encrypted backup somewhere safe. ".repeat(3));
        app.notice = "A synthetic error with a clear next step: inspect the last operation.".into();
        app.ui.notice_error = true;
        render(&app, &format!("{prefix}-warnings"), 480, 480, 1.3);
        app.ui.confirm_close = Some(iced::window::Id::unique());
        render(&app, &format!("{prefix}-close"), 480, 480, 1.3);
    }
}

#[test]
fn large_synthetic_vault_search_finds_metadata_without_hiding_advanced_search() {
    let mut app = tests::app();
    app.request_state = RequestState::Idle;
    app.notice.clear();
    app.connection.running = true;
    app.connection.session = Some("synthetic-session".into());
    app.items = (0..2000)
        .map(|id| ItemSummary {
            id: id + 1,
            revision: 1,
            name: format!("Account {id:04}"),
            username: Some(format!("user{id}@example.test")),
            kind: ItemKind::Login,
            urls: vec![format!("https://site{id}.example.test")],
            has_totp: false,
            has_duo: false,
        })
        .collect();
    let started = Instant::now();
    let first = render(&app, "large-vault", 1060, 800, 1.0);
    assert!(first.1.iter().any(|label| label == "Account 0000"));
    assert!(first.1.iter().any(|label| label == "Next page"));
    assert!(!first.1.iter().any(|label| label == "Account 1999"));
    app.ui.item_page = 39;
    let last = render(&app, "large-vault-last", 1060, 800, 1.0);
    assert!(last.1.iter().any(|label| label == "Account 1999"));
    assert!(!last.1.iter().any(|label| label == "Account 0000"));
    eprintln!("2000-item real layout and render: {:?}", started.elapsed());
    app.query = "site1734.example.test".into();
    assert_eq!(&*app.matching_items(), &[1734]);
    app.query = "user1900@".into();
    assert_eq!(&*app.matching_items(), &[1900]);
}

#[test]
fn dynamic_banners_preserve_editor_focus_across_view_updates() {
    use renderer::Renderer as _;
    let mut app = tests::app();
    app.connection.running = true;
    app.request_state = RequestState::Idle;
    app.connection.session = Some("synthetic-session".into());
    app.editor = Editor::new(Draft::default());
    let size = Size::new(1060.0, 760.0);
    let mut renderer = iced::Renderer::new(iced::Font::DEFAULT, iced::Pixels(16.0));
    renderer.reset(Rectangle::with_size(size));
    let mut tree = widget::Tree::empty();
    for pass in 0..3 {
        if pass == 1 {
            app.editor.as_mut().unwrap().dirty = true;
        } else if pass == 2 {
            app.warning = Some("Synthetic connection warning".into());
        }
        let mut element = app.view();
        tree.diff(element.as_widget());
        let node = element.as_widget_mut().layout(
            &mut tree,
            &renderer,
            &layout::Limits::new(Size::ZERO, size),
        );
        if pass == 0 {
            element.as_widget_mut().operate(
                &mut tree,
                layout::Layout::new(&node),
                &renderer,
                &mut operation::focusable::focus("item-notes".into()),
            );
        }
        let mut builder = iced_winit::a11y::TreeBuilder::new("Password Manager");
        element.as_widget_mut().operate(
            &mut tree,
            layout::Layout::new(&node),
            &renderer,
            &mut builder,
        );
        let accessible = builder.build();
        let focused = accessible
            .update
            .nodes
            .iter()
            .find(|(id, _)| *id == accessible.update.focus)
            .unwrap();
        assert_eq!(focused.1.label(), Some("Private notes"), "pass {pass}");
    }
}
