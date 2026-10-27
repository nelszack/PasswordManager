use super::*;
use crate::gui::widgets::{button, checkbox, pick_list, scrollable, text_input};
use iced::widget::button as button_style;
use iced::{
    Alignment, Fill, Length,
    widget::{Column, column, container, row, rule, text, text_editor},
};

fn action<'a>(label: &'a str, message: Message, enabled: bool) -> crate::gui::widgets::Button<'a> {
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

fn primary<'a>(label: &'a str, message: Message, enabled: bool) -> crate::gui::widgets::Button<'a> {
    action(label, message, enabled).style(|theme, status| {
        let mut style = button_style::primary(theme, status);
        style.border.radius = 8.0.into();
        style
    })
}

fn label(value: &str) -> iced::widget::Text<'_> {
    text(value).size(14)
}

fn error<'a>(value: impl Into<String>) -> iced::widget::Text<'a> {
    text(value.into()).size(14).style(text::danger)
}

fn disclosure<'a>(
    title: &'a str,
    expanded: bool,
    section: presentation::Disclosure,
    enabled: bool,
) -> Element<'a, Message> {
    action(
        if expanded { "Hide options" } else { title },
        Message::Disclosure(section),
        enabled,
    )
    .into()
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

fn navigation(app: &App) -> Element<'_, Message> {
    let mut tabs = row![].spacing(8);
    for (title, tab) in [
        ("Vault", Tab::Vault),
        ("Generator", Tab::Generator),
        ("Tools", Tab::Tools),
        ("Settings", Tab::Settings),
    ] {
        let selected = app.tab == tab;
        tabs = tabs.push(
            action(title, Message::Tab(tab), !app.busy)
                .padding(if app.compact() { [9, 10] } else { [11, 14] })
                .style(move |theme: &Theme, status| {
                    if selected {
                        let mut style = button_style::primary(theme, status);
                        style.border = iced::Border {
                            color: theme.palette().primary,
                            width: 2.0,
                            radius: 8.0.into(),
                        };
                        style
                    } else {
                        quiet_button(theme, status)
                    }
                }),
        );
    }
    tabs.wrap().into()
}

pub(super) fn view(app: &App) -> Element<'_, Message> {
    let status = if !app.running {
        "Offline".to_owned()
    } else if app.session.is_some() {
        if let Some((id, _)) = app
            .ui
            .active_vault
            .as_ref()
            .filter(|(_, session)| app.session.as_ref() == Some(session))
        {
            let name = app.names.label(id, &app.vaults);
            let limit = if app.compact() { 12 } else { 32 };
            let name = if name.chars().count() > limit {
                format!("{}…", name.chars().take(limit - 1).collect::<String>())
            } else {
                name
            };
            format!("{name} · Unlocked")
        } else {
            "Vault unlocked".into()
        }
    } else {
        "Vault locked".into()
    };
    let header = row![
        column![
            text(if app.ui.width < 430.0 {
                "Passwords"
            } else {
                "Password Manager"
            })
            .size(if app.compact() { 18 } else { 23 })
            .width(Fill),
            text(status).size(14)
        ]
        .spacing(4)
        .width(Fill),
        action(
            "Shortcuts",
            Message::Disclosure(presentation::Disclosure::Shortcuts),
            !app.busy
        )
        .padding(if app.compact() { [9, 10] } else { [11, 14] }),
        action(
            if app.compact() { "Lock" } else { "Lock vault" },
            Message::Lock,
            app.running && app.session.is_some()
        )
        .padding(if app.compact() { [9, 10] } else { [11, 14] }),
    ]
    .spacing(8)
    .align_y(Alignment::Center);
    let mut page = column![header, navigation(app)].spacing(12);
    if let Some(id) = &app.pending {
        let mut recovery = column![
            text("Review the last change before continuing").size(17),
            text("The result of a previous change is uncertain. Inspect the vault before allowing new changes.").size(14),
            text(format!("Operation {id}")).size(14),
            primary("Check last change", Message::Reconcile, !app.busy && app.running),
        ].spacing(8);
        if app.reviewed {
            recovery = recovery.push(action(
                "I inspected the vault; allow new changes",
                Message::Acknowledge,
                !app.busy,
            ));
        }
        page = page.push(scrollable(panel(recovery)).height(Length::Fixed(150.0)));
    }
    if let Some(warning) = &app.warning {
        page = page.push(panel(text(warning).size(14).style(text::danger)));
    }
    if let Some(target) = app
        .workspace
        .duo_watch_target
        .as_ref()
        .filter(|_| app.workspace.watch_duo)
    {
        page = page.push(
            row![
                text(format!("Watching Duo · {}", target.choice))
                    .size(14)
                    .width(Fill),
                action(
                    "Review requests",
                    Message::OpenToolItem(target.choice.id),
                    !app.busy
                ),
                action(
                    "Stop watching",
                    Message::Workflow(workflows::Event::Toggle(workflows::Toggle::WatchDuo, false)),
                    !app.busy
                ),
            ]
            .spacing(8)
            .wrap(),
        );
    }
    let content = if app.ui.shortcuts {
        shortcuts()
    } else {
        match app.tab {
            Tab::Vault if !app.running => stopped(app),
            Tab::Vault if app.session.is_none() => unlock(app),
            Tab::Vault => vault(app),
            Tab::Generator => generator(app),
            Tab::Settings => settings(app),
            Tab::Tools => app.workspace.view(app),
        }
    };
    let short = app.ui.height < 460.0 || (app.pending.is_some() && app.ui.height < 680.0);
    if short {
        // At very small heights, scroll the entire page, including its chrome.
        // Each inner pane retains a useful viewport instead of collapsing.
        page = page.push(container(content).width(Fill).height(520));
    } else {
        page = page.push(container(content).width(Fill).height(Fill));
    }
    if app.draft.is_some() && app.tab != Tab::Vault {
        page = page.push(action(
            "Return to item draft",
            Message::Tab(Tab::Vault),
            !app.busy,
        ));
    }
    page = page.push(feedback(app));
    let page: Element<'_, Message> = if short {
        scrollable(page)
            .id("short-page")
            .spacing(10)
            .height(Fill)
            .into()
    } else {
        page.into()
    };
    container(page)
        .padding(if app.compact() { 12 } else { 20 })
        .width(Fill)
        .height(Fill)
        .into()
}

fn shortcuts() -> Element<'static, Message> {
    let command = if cfg!(target_os = "macos") {
        "Cmd"
    } else {
        "Ctrl"
    };
    let mut keys = column![
        text("Keyboard shortcuts").size(25),
        text("Use Tab and Shift+Tab to move between controls. Focus scrolls into view.").size(15),
    ]
    .spacing(16);
    for (key, description) in [
        ("F", "Search your items"),
        ("N", "Add an item"),
        ("S", "Save the current item or settings"),
        ("E", "Edit the selected item"),
        ("Shift+C", "Copy username"),
        ("Shift+O", "Open the first website"),
        ("1–4", "Switch between the four main tabs"),
        ("L", "Lock the vault"),
        ("/", "Open or close this guide"),
    ] {
        keys = keys.push(
            row![
                text(format!("{command}+{key}")).width(140),
                text(description).width(Fill)
            ]
            .spacing(12),
        );
    }
    keys = keys.push(text("Enter / Space activates a control. Arrow keys change selections. Escape hides revealed secrets.").size(14));
    panel(
        column![
            scrollable(keys).height(Fill),
            action(
                "Close shortcuts",
                Message::Disclosure(presentation::Disclosure::Shortcuts),
                true
            ),
        ]
        .spacing(16),
    )
    .height(Fill)
    .width(Fill)
    .into()
}

fn feedback(app: &App) -> Element<'_, Message> {
    let message = if app.busy {
        "Working…"
    } else if app.notice.is_empty() {
        "Ready"
    } else {
        &app.notice
    };
    let mut content = column![].spacing(3);
    if app.ui.notice_error {
        content = content.push(text("Needs attention").size(14));
    }
    content = content.push(text(message).size(14));
    let mut line = row![container(scrollable(content)).width(Fill).height(Fill)]
        .spacing(10)
        .align_y(Alignment::Center);
    if app
        .ui
        .undo_trash
        .as_ref()
        .is_some_and(|(_, session)| app.session.as_ref() == Some(session))
        && app.tab == Tab::Vault
        && app.draft.is_none()
    {
        line = line.push(action(
            "Undo deletion",
            Message::UndoDelete,
            !app.busy && app.pending.is_none(),
        ));
    }
    if !app.notice.is_empty() {
        line = line.push(action("Dismiss", Message::DismissNotice, !app.busy));
    }
    container(line)
        .padding([4, 8])
        .height(52)
        .width(Fill)
        .style(if app.ui.notice_error {
            container::danger
        } else {
            container::transparent
        })
        .into()
}

fn connection_controls(app: &App) -> Column<'_, Message> {
    let valid_port = app
        .connection_port
        .trim()
        .parse::<u16>()
        .is_ok_and(|port| port > 0);
    let mut controls = column![
        label("Temporary connection port (1–65535)"),
        row![
            text_input("Port", &app.connection_port)
                .padding(10)
                .on_input_maybe((!app.busy).then_some(Message::ConnectionPort))
                .on_submit_maybe((!app.busy && valid_port).then_some(Message::UseConnectionPort)),
            action(
                "Connect",
                Message::UseConnectionPort,
                !app.busy && valid_port
            ),
        ]
        .spacing(10),
        text("Connect to an existing server using this port for this desktop session.").size(14),
    ]
    .spacing(8);
    if !valid_port {
        controls = controls.push(text("Enter a port between 1 and 65535.").size(14));
    }
    controls
}

fn stopped(app: &App) -> Element<'_, Message> {
    let form = column![
        text("Connect to your vault").size(27),
        text("Start the local service to open your encrypted vault. The browser extension uses the same service.").size(15),
        primary("Start local service", Message::Connect, !app.busy),
        rule::horizontal(1),
        text("Connect to an existing service").size(18),
        connection_controls(app),
    ].spacing(16);
    container(
        panel(scrollable(form).id("connection-form"))
            .max_width(620)
            .height(Fill),
    )
    .center_x(Fill)
    .height(Fill)
    .into()
}

fn unlock(app: &App) -> Element<'_, Message> {
    let enabled = !app.busy;
    if app.vaults.is_empty() && !app.creating {
        return container(container(scrollable(panel(column![
            text("Your passwords. Your vault.").size(28),
            text("Keep logins, notes, and other secrets together in an encrypted vault on this device.").size(16),
            primary("Create your first vault", Message::Creating(true), app.writes_allowed()),
            action("Import passwords", Message::OpenFileTool(workflows::FileOperation::Import), enabled),
            action("Restore an encrypted backup", Message::OpenFileTool(workflows::FileOperation::Restore), enabled),
            rule::horizontal(1),
            text("Already have a vault on this device?").size(14),
            action("Find existing vaults", Message::RefreshVaults, enabled),
        ].spacing(18)).max_width(580)).height(Fill)).max_width(620)).center_x(Fill).height(Fill).into();
    }
    let mut form = column![
        text(if app.creating {
            "Create your vault"
        } else {
            "Welcome back"
        })
        .size(28),
        text(if app.creating {
            "One master password protects everything in this vault."
        } else {
            "Unlock your vault to access your items."
        })
        .size(15),
    ]
    .spacing(14);
    if !app.creating {
        let choices = app.vault_choices();
        let selected = choices
            .iter()
            .find(|choice| Some(&choice.id) == app.vault.as_ref())
            .cloned();
        form = form.push(label("Vault")).push(
            pick_list(choices, selected, |choice: vault_names::Choice| {
                Message::Vault(choice.id)
            })
            .width(Fill)
            .padding(12),
        );
    }
    let using_key = !app.creating && app.ui.unlock_advanced && !app.key_path.is_empty();
    if app.creating {
        form = form.push(
            column![
                label("Vault name"),
                text_input("Personal or Work", &app.ui.vault_name)
                    .padding(12)
                    .on_input(Message::VaultName),
            ]
            .spacing(6),
        );
        if let Err(message) = vault_names::validate_name(&app.ui.vault_name) {
            form = form.push(error(message));
        }
    }
    if !using_key {
        form = form.push(
            column![
                label("Master password"),
                text_input("Enter master password", app.master.expose())
                    .id("master-password")
                    .secure(true)
                    .padding(12)
                    .on_input_maybe(
                        enabled.then_some(|value: String| Message::Master(value.into()))
                    )
                    .on_submit_maybe((enabled && !app.creating).then_some(Message::Unlock)),
            ]
            .spacing(6),
        );
    }
    if app.creating {
        form = form
            .push(text("Use 14+ characters, such as several unrelated words.").size(14))
            .push(
                column![
                    label("Confirm master password"),
                    text_input("Enter it again", app.confirmation.expose())
                        .secure(true)
                        .padding(12)
                        .on_input_maybe(
                            enabled.then_some(|value: String| Message::ConfirmMaster(value.into()))
                        )
                        .on_submit_maybe(
                            (app.writes_allowed()
                                && app.master == app.confirmation
                                && !app.master.is_empty()
                                && app.ui.master_error.is_none()
                                && vault_names::validate_name(&app.ui.vault_name).is_ok())
                            .then_some(Message::Create)
                        )
                ]
                .spacing(6),
            );
        if !app.master.is_empty()
            && let Some(message) = app.ui.master_error
        {
            form = form.push(error(message));
        }
        if !app.confirmation.is_empty() && app.master != app.confirmation {
            form = form.push(error("The passwords do not match yet."));
        }
    } else {
        form = form.push(disclosure(
            "Advanced unlock options",
            app.ui.unlock_advanced,
            presentation::Disclosure::Unlock,
            enabled,
        ));
        if app.ui.unlock_advanced {
            form = form
                .push(label(
                    "Lock after inactivity (15m, 1h, or seconds; 0 disables)",
                ))
                .push(
                    text_input("15m", &app.unlock_timeout)
                        .padding(12)
                        .on_input(Message::UnlockTimeout),
                );
            if let Err(message) = password_manager::config::parse_duration(&app.unlock_timeout) {
                form = form.push(error(message));
            }
            if let Some(id) = &app.vault {
                form = form
                    .push(label("Vault file (advanced)"))
                    .push(text(id).size(14));
            }
            form = form
                .push(label("External key file (optional)"))
                .push(
                    row![
                        text_input("Absolute path to your key file", app.key_path.expose())
                            .padding(12)
                            .on_input_maybe(
                                enabled.then_some(|value: String| Message::KeyPath(value.into()))
                            ),
                        action("Browse…", Message::BrowseKey, enabled)
                    ]
                    .spacing(8),
                )
                .push(
                    text("A key file replaces the master password for key-based vaults.").size(14),
                )
                .push(action(
                    "Refresh vault list",
                    Message::RefreshVaults,
                    enabled,
                ));
        }
        form = form.push(rule::horizontal(1)).push(action(
            "Create another vault",
            Message::Creating(true),
            app.writes_allowed(),
        ));
    }
    let actions = if app.creating {
        row![
            primary(
                "Create vault",
                Message::Create,
                app.writes_allowed()
                    && app.master == app.confirmation
                    && !app.master.is_empty()
                    && app.ui.master_error.is_none()
                    && vault_names::validate_name(&app.ui.vault_name).is_ok()
            ),
            action("Back", Message::Creating(false), enabled)
        ]
        .spacing(10)
        .wrap()
    } else {
        row![primary(
            "Unlock vault",
            Message::Unlock,
            enabled && (!app.master.is_empty() || using_key)
        )]
        .spacing(10)
        .wrap()
    };
    container(
        panel(
            column![
                scrollable(form).id("unlock-form").spacing(8).height(Fill),
                rule::horizontal(1),
                actions
            ]
            .spacing(12),
        )
        .max_width(580)
        .height(Fill),
    )
    .center_x(Fill)
    .height(Fill)
    .into()
}

fn vault(app: &App) -> Element<'_, Message> {
    let mut entries = Column::new().spacing(6);
    let mut count = 0;
    for item in app.items.iter().filter(|item| app.item_matches(item)) {
        count += 1;
        let selected = app
            .item
            .as_ref()
            .is_some_and(|selected| selected.id == item.id);
        let username = item
            .username
            .as_deref()
            .filter(|username| !username.is_empty());
        let kind = model::profile(item.kind).title;
        let subtitle = username.map_or_else(
            || kind.to_owned(),
            |username| format!("{username} · {kind}"),
        );
        let entry_content = column![text(&item.name).size(16), text(subtitle).size(14)].spacing(5);
        entries = entries.push(
            button(entry_content)
                .width(Fill)
                .padding(12)
                .style(if selected {
                    button_style::primary
                } else {
                    quiet_button
                })
                .on_press_maybe(
                    (!app.busy).then_some(Message::Navigate(Navigate::Select(item.id))),
                ),
        );
    }
    if count == 0 {
        entries = entries.push(
            text(if app.items.is_empty() {
                "Your first item starts here."
            } else {
                "No matching items. Try another search or clear the filters."
            })
            .size(15),
        );
        if !app.items.is_empty() {
            entries = entries.push(action(
                "Clear search",
                Message::Search(String::new()),
                !app.busy,
            ));
            entries = entries.push(action(
                "Show all types",
                Message::FilterKind(None),
                !app.busy,
            ));
        }
    }
    let mut kinds = vec!["All types".to_owned()];
    kinds.extend(
        model::KINDS
            .iter()
            .map(|kind| model::profile(*kind).title.to_owned()),
    );
    let selected_kind = app
        .ui
        .kind
        .map(|kind| model::profile(kind).title.to_owned())
        .unwrap_or_else(|| "All types".into());
    let sidebar = column![
        row![
            text("Your items").size(22).width(Fill),
            primary(
                "Add item",
                Message::Navigate(Navigate::New),
                app.writes_allowed()
            )
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        row![
            text_input("Search items", &app.query)
                .id("vault-search")
                .padding(10)
                .width(Fill)
                .on_input(Message::Search),
            pick_list(kinds, Some(selected_kind), |selected| Message::FilterKind(
                model::KINDS
                    .iter()
                    .find(|kind| model::profile(**kind).title == selected)
                    .copied()
            ))
            .width(135)
            .padding(10),
        ]
        .spacing(8),
        row![
            text(format!("{count} of {} items", app.items.len()))
                .size(14)
                .width(Fill),
            action("Refresh", Message::Navigate(Navigate::Refresh), !app.busy)
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        scrollable(entries.push(action(
            "Advanced search",
            Message::OpenTools(workflows::Section::Search),
            !app.busy
        )))
        .id("item-list")
        .spacing(8)
        .height(Fill),
    ]
    .spacing(12)
    .height(Fill);
    let detail = if let Some(draft) = &app.draft {
        editor(app, draft)
    } else if let Some(item) = &app.item {
        details(app, item)
    } else {
        column![
            panel(column![
                text(if app.items.is_empty() { "Add your first item" } else { "Select an item" }).size(27),
                text(if app.items.is_empty() { "Save a login, private note, card, or another secret. You can also import your passwords." } else { "Choose an item to copy its sign-in details, open a website, or make a change." }).size(16),
                row![primary("Add item",Message::Navigate(Navigate::New),app.writes_allowed()),
                    action("Import passwords",Message::OpenFileTool(workflows::FileOperation::Import),!app.busy)].spacing(10).wrap(),
            ].spacing(16)).width(Fill),
            panel(column![
                text("Keep your vault in good shape").size(19),
                text(format!("{} items · Encrypted on this device",app.items.len())).size(14),
                row![action("Check vault health",Message::OpenTools(workflows::Section::Audit),!app.busy),
                    action("Create a backup",Message::OpenFileTool(workflows::FileOperation::Backup),!app.busy)].spacing(10).wrap(),
            ].spacing(12)).width(Fill),
        ].spacing(16).width(Fill).height(Fill).into()
    };
    let panes: Element<'_, Message> = if app.compact() {
        if app.draft.is_some() {
            detail
        } else if app.item.is_some() {
            column![
                action(
                    "Back to items",
                    Message::Navigate(Navigate::Close),
                    !app.busy
                ),
                detail
            ]
            .spacing(10)
            .height(Fill)
            .into()
        } else {
            sidebar.width(Fill).into()
        }
    } else {
        row![
            sidebar.width(310),
            container(detail).width(Fill).height(Fill)
        ]
        .spacing(20)
        .height(Fill)
        .into()
    };
    let mut body = column![].spacing(12).height(Fill);
    if app.deferred.is_some() {
        body = body.push(panel(
            column![
                text("Keep your unsaved changes?").size(18),
                text(
                    "Your item has not been saved. Keep editing, or discard the draft to continue."
                )
                .size(14),
                row![
                    primary("Keep editing", Message::KeepEditing, !app.busy),
                    action("Discard changes", Message::Discard, !app.busy)
                        .style(button_style::danger)
                ]
                .spacing(8)
                .wrap(),
            ]
            .spacing(10),
        ));
    }
    body.push(panes).into()
}

fn details<'a>(app: &'a App, item: &'a ItemDetail) -> Element<'a, Message> {
    let profile = model::profile(item.kind);
    let mut content = column![
        row![
            text(&item.name).size(24).width(Fill),
            text(profile.title).size(14)
        ]
        .spacing(12)
        .align_y(Alignment::Center)
    ]
    .spacing(10);
    if app.delete_confirm {
        content = content
            .push(rule::horizontal(1))
            .push(text("Move this item to encrypted trash?"))
            .push(
                row![
                    action("Cancel", Message::CancelDelete, !app.busy),
                    action(
                        "Move to trash",
                        Message::ConfirmDelete,
                        app.writes_allowed()
                    )
                    .style(button_style::danger)
                ]
                .spacing(10)
                .wrap(),
            );
    }
    if app
        .workspace
        .prepared
        .as_ref()
        .is_some_and(|prepared| matches!(prepared.action, workflows::Action::Respond(..)))
    {
        content = content.push(app.workspace.duo_confirmation(app));
    }
    content = content
        .push(rule::horizontal(1))
        .push(
            column![
                label(profile.owner),
                row![
                    text(item.username.as_deref().unwrap_or("—")).width(Fill),
                    action(
                        if item.kind == ItemKind::Login {
                            "Copy username"
                        } else {
                            "Copy"
                        },
                        Message::CopyUsername,
                        app.copying_allowed()
                            && item
                                .username
                                .as_ref()
                                .is_some_and(|value| !value.is_empty())
                    )
                ]
                .spacing(10)
                .align_y(Alignment::Center),
            ]
            .spacing(4),
        )
        .push(
            column![
                label(profile.secret),
                row![
                    text(item.password.as_ref().map(SecretString::expose).unwrap_or(
                        if item.has_secret {
                            "••••••••••••"
                        } else {
                            "No primary secret"
                        }
                    ))
                    .width(Fill),
                    action(
                        if app.reveal_until.is_some() {
                            "Hide secrets"
                        } else {
                            "Reveal for 15 seconds"
                        },
                        Message::Reveal,
                        !app.busy && item.has_secret
                    ),
                ]
                .spacing(10)
                .align_y(Alignment::Center)
            ]
            .spacing(4),
        );
    if app.conf.clipboard.timeout == 0 {
        content = content.push(text("Copying is off in Settings → Security.").size(13));
    }
    if item.has_totp || item.has_duo {
        content = content
            .push(rule::horizontal(1))
            .push(app.workspace.account_authenticators(app, item));
    }
    if !item.urls.is_empty() {
        content = content.push(label("URLs"));
        for (index, url) in item.urls.iter().enumerate() {
            content = content.push(
                row![
                    text(url).size(14).width(Fill),
                    action(
                        "Open website",
                        Message::OpenWebsite(index),
                        !app.busy && website::address(url).is_ok()
                    ),
                ]
                .spacing(10)
                .align_y(Alignment::Center),
            );
        }
    }
    if let Some(notes) = &item.notes
        && !notes.is_empty()
    {
        content = content
            .push(label("Notes"))
            .push(text(notes.expose()).size(14));
    }
    if !item.fields.is_empty() {
        content = content.push(label("Custom fields"));
        for (index, field) in item.fields.iter().enumerate() {
            let target = FieldTarget {
                id: item.id,
                revision: item.revision,
                index,
            };
            let mut controls = row![].spacing(8);
            if field.secret {
                controls = controls.push(action(
                    if field.value.is_some() {
                        "Hide field"
                    } else {
                        "Reveal field for 15 seconds"
                    },
                    if field.value.is_some() {
                        Message::HideField(target)
                    } else {
                        Message::RevealField(target)
                    },
                    !app.busy,
                ));
            }
            controls = controls.push(action(
                "Copy field",
                Message::CopyField(target),
                app.copying_allowed(),
            ));
            content = content.push(
                column![
                    text(&field.name).size(14),
                    text(
                        field
                            .value
                            .as_ref()
                            .map(SecretString::expose)
                            .unwrap_or("••••••••")
                    )
                    .size(14),
                    controls.wrap(),
                ]
                .spacing(6),
            );
        }
    }
    content = content.push(
        row![
            action(
                "Password history",
                Message::OpenItemTools(item.id),
                !app.busy
            ),
            action("Move to trash…", Message::Delete, app.writes_allowed()).style(quiet_danger),
        ]
        .spacing(10)
        .wrap(),
    );
    content = content.push(
        text(format!(
            "Created {}\nModified {}",
            presentation::display_date(&item.created),
            presentation::display_date(&item.modified)
        ))
        .size(13),
    );
    panel(
        column![
            scrollable(content)
                .id("account-details")
                .spacing(8)
                .height(Fill),
            rule::horizontal(1),
            row![
                primary(
                    "Copy secret",
                    Message::Copy,
                    app.copying_allowed() && item.has_secret
                ),
                action("Edit item", Message::Edit, app.writes_allowed())
            ]
            .spacing(10)
            .wrap(),
        ]
        .spacing(12),
    )
    .height(Fill)
    .width(Fill)
    .into()
}

fn editor<'a>(app: &'a App, draft: &'a Draft) -> Element<'a, Message> {
    let enabled = !app.busy;
    let profile = model::profile(draft.kind);
    let mut name = column![
        label("Name (required)"),
        text_input(profile.name_hint, &draft.name)
            .id("item-name")
            .padding(10)
            .on_input_maybe(enabled.then_some(Message::Name)),
    ]
    .spacing(4)
    .width(Fill);
    if draft.dirty && draft.name.trim().is_empty() {
        name = name.push(error("Give this item a name so you can find it later."));
    }
    let kind = column![
        label("Item type"),
        pick_list(
            model::KINDS.map(model::KindChoice),
            Some(model::KindChoice(draft.kind)),
            |choice| Message::Kind(choice.0)
        )
        .padding(8)
        .width(Fill)
    ]
    .spacing(4)
    .width(168);
    let owner = column![
        label(profile.owner),
        text_input(profile.owner, &draft.username)
            .padding(10)
            .on_input_maybe(enabled.then_some(Message::Username))
    ]
    .spacing(4)
    .width(Fill);
    let mut secret = column![label(profile.secret)].spacing(4).width(Fill);
    if draft.id.is_some() {
        secret = secret.push(
            checkbox(draft.replace_password)
                .label("Replace primary secret")
                .on_toggle(Message::ReplacePassword),
        );
    }
    if draft.id.is_none() || draft.replace_password {
        if draft.multiline {
            secret = secret.push(
                text_editor(&draft.secret_editor)
                    .placeholder("Private key or multiline secret")
                    .height(160)
                    .padding(10)
                    .on_action(Message::SecretEdit),
            );
        } else {
            let mut entry = row![
                text_input(profile.secret, draft.password.expose())
                    .id("item-secret")
                    .secure(!app.ui.editor_show_secret)
                    .padding(10)
                    .width(Fill)
                    .on_input_maybe(
                        enabled.then_some(|value: String| Message::Password(value.into()))
                    ),
                action(
                    if app.ui.editor_show_secret {
                        "Hide"
                    } else {
                        "Show"
                    },
                    Message::ShowEditorSecret(!app.ui.editor_show_secret),
                    enabled
                )
                .padding([9, 10]),
            ]
            .spacing(8)
            .align_y(Alignment::Center);
            if matches!(draft.kind, ItemKind::Login | ItemKind::Wifi) {
                entry = entry.push(action("Generate", Message::Generate, enabled).padding([9, 10]));
            }
            secret = secret.push(entry);
        }
        if matches!(draft.kind, ItemKind::SshKey | ItemKind::SecureNote) {
            secret = secret.push(
                checkbox(draft.multiline)
                    .label("Use multiline editor (visible while editing)")
                    .on_toggle(Message::MultilineSecret),
            );
        }
    }
    let credentials: Element<'_, Message> =
        if !app.compact() && app.ui.width >= 1120.0 && !draft.multiline {
            row![owner, secret].spacing(14).into()
        } else {
            column![owner, secret].spacing(8).into()
        };
    let mut form = column![row![name, kind].spacing(12), credentials].spacing(8);
    if !profile.suggested.is_empty() {
        form = form.push(text(format!("{} details", profile.title)).size(19));
        for &(name, secret) in profile.suggested {
            let slot = draft
                .fields
                .iter()
                .enumerate()
                .find(|(_, field)| !field.removed && field.name.eq_ignore_ascii_case(name));
            let existing = slot.map(|(_, field)| field);
            let value = existing.map(|field| field.value.expose()).unwrap_or("");
            let hidden = existing.is_some_and(|field| field.hidden && !field.value_edited);
            let input =
                text_input(
                    if hidden {
                        "Unchanged; type a replacement to edit"
                    } else {
                        "Optional"
                    },
                    value,
                )
                .id(format!("template-{name}"))
                .secure(secret || existing.is_some_and(|field| field.secret))
                .padding(12)
                .on_input_maybe(enabled.then_some(move |value: String| {
                    Message::TemplateValue(name, secret, value.into())
                }));
            let mut line = row![input].spacing(8).align_y(Alignment::Center);
            if let Some((index, _)) = slot {
                line = line.push(action("Clear", Message::RemoveField(index), enabled));
            }
            form = form.push(column![label(name), line].spacing(6));
        }
    }
    let mut websites = column![
        row![
            label("Websites (optional)").width(Fill),
            action("Add website", Message::AddUrl, enabled).padding([7, 10])
        ]
        .align_y(Alignment::Center)
    ]
    .spacing(6);
    for (index, url) in draft.urls.iter().enumerate() {
        websites = websites.push(
            row![
                text_input("https://example.com", url)
                    .padding(10)
                    .on_input_maybe(enabled.then_some(move |value| Message::Url(index, value))),
                action("Remove", Message::RemoveUrl(index), enabled).padding([9, 10])
            ]
            .spacing(8),
        );
    }
    form = form
        .push(websites)
        .push(
            column![
                label("Notes (optional)"),
                text_editor(&draft.notes)
                    .placeholder("Private notes")
                    .height(88)
                    .padding(10)
                    .on_action(Message::Notes)
            ]
            .spacing(6),
        )
        .push(rule::horizontal(1))
        .push(disclosure(
            "Custom fields & advanced options",
            app.ui.editor_advanced,
            presentation::Disclosure::Editor,
            enabled,
        ));
    if app.ui.editor_advanced {
        form = form.push(text(profile.guidance).size(14));
        if draft.id.is_none() {
            form = form
                .push(label("Copy primary secret after saving"))
                .push(
                    pick_list(
                        model::ClipboardPolicy::ALL.as_slice(),
                        Some(draft.copy_policy),
                        Message::CopyPolicy,
                    )
                    .padding(12)
                    .width(Fill),
                )
                .push(text("A clipboard timeout of 0 disables copying.").size(14));
        }
        if draft.id.is_none() || draft.replace_password {
            form = form.push(
                checkbox(draft.multiline)
                    .label("Edit as a multiline secret (visible while editing)")
                    .on_toggle(Message::MultilineSecret),
            );
        }
        form = form.push(text("Custom fields").size(18));
        for (index, field) in draft.fields.iter().enumerate().filter(|(_, field)| {
            !field.removed
                && !profile
                    .suggested
                    .iter()
                    .any(|(name, _)| field.name.eq_ignore_ascii_case(name))
        }) {
            let mut custom = column![
                label("Field name"),
                text_input("e.g. Account number", &field.name)
                    .padding(12)
                    .on_input_maybe(
                        enabled.then_some(move |value| Message::FieldName(index, value))
                    ),
                label("Field value"),
                text_input(
                    if field.hidden && !field.value_edited {
                        "Unchanged; enter a replacement to edit"
                    } else {
                        "Value"
                    },
                    field.value.expose()
                )
                .secure(field.secret)
                .padding(12)
                .on_input_maybe(
                    enabled
                        .then_some(move |value: String| Message::FieldValue(index, value.into()))
                ),
                row![
                    checkbox(field.secret)
                        .label("Keep value secret")
                        .on_toggle_maybe(
                            enabled.then_some(move |value| Message::FieldSecret(index, value))
                        ),
                    action("Remove field", Message::RemoveField(index), enabled)
                ]
                .spacing(8)
                .wrap(),
            ]
            .spacing(8);
            if let Some(message) = draft.field_error(index) {
                custom = custom.push(error(message));
            }
            form = form.push(panel(custom));
        }
        form = form
            .push(action("Add custom field", Message::AddField, enabled))
            .push(
                text("Existing hidden values are preserved unless you explicitly replace them.")
                    .size(14),
            );
    }
    form = form.push(rule::horizontal(1)).push(disclosure(
        "Authenticator & Duo enrollment",
        app.ui.editor_authenticators,
        presentation::Disclosure::Authenticators,
        enabled,
    ));
    if app.ui.editor_authenticators {
        form = form.push(app.workspace.authenticator_editor(app));
    }
    let mut footer = column![].spacing(8);
    if draft.dirty
        && let Err(message) = draft.validate()
    {
        footer = footer.push(error(message));
    }
    footer = footer.push(
        row![
            primary(
                "Save item",
                Message::Save,
                app.writes_allowed() && draft.validate().is_ok()
            ),
            action("Cancel", Message::Navigate(Navigate::Close), enabled),
            text(if draft.dirty {
                "Unsaved changes"
            } else {
                "Save to keep changes"
            })
            .size(13)
        ]
        .spacing(8)
        .align_y(Alignment::Center)
        .wrap(),
    );
    let heading = text(if draft.id.is_some() {
        "Edit item"
    } else {
        "New item"
    })
    .size(24);
    panel(
        column![
            scrollable(column![heading, form].spacing(8))
                .id("credential-editor")
                .spacing(8)
                .height(Fill),
            rule::horizontal(1),
            footer
        ]
        .spacing(12),
    )
    .height(Fill)
    .width(Fill)
    .into()
}

fn generator(app: &App) -> Element<'_, Message> {
    use super::generator::{Event, Policy, Toggle};
    let mut form = column![
        checkbox(app.passphrase)
            .label("Generate a memorable passphrase")
            .on_toggle(Message::Passphrase),
        label(if app.passphrase {
            "Number of words (1–255)"
        } else {
            "Password length (1–255)"
        }),
        text_input(
            if app.passphrase { "6" } else { "20" },
            if app.passphrase {
                &app.words
            } else {
                &app.generator_length
            }
        )
        .padding(12)
        .on_input(if app.passphrase {
            Message::Words
        } else {
            Message::GeneratorLength
        })
        .on_submit(Message::Generate),
    ]
    .spacing(14);
    if app.passphrase {
        form = form.push(label("Word separator")).push(
            text_input("-", &app.generator.separator)
                .padding(12)
                .on_input(|value| Message::Generator(Event::Separator(value))),
        );
    } else {
        form = form
            .push(
                row![
                    checkbox(app.generator.uppercase)
                        .label("A–Z")
                        .on_toggle(|value| Message::Generator(Event::Toggle(
                            Toggle::Uppercase,
                            value
                        ))),
                    checkbox(app.generator.lowercase)
                        .label("a–z")
                        .on_toggle(|value| Message::Generator(Event::Toggle(
                            Toggle::Lowercase,
                            value
                        ))),
                    checkbox(app.generator.digits)
                        .label("0–9")
                        .on_toggle(|value| Message::Generator(Event::Toggle(
                            Toggle::Digits,
                            value
                        ))),
                    checkbox(app.generator.symbols)
                        .label("Symbols")
                        .on_toggle(|value| Message::Generator(Event::Toggle(
                            Toggle::Symbols,
                            value
                        ))),
                ]
                .spacing(18)
                .wrap(),
            )
            .push(
                checkbox(app.generator.ambiguous)
                    .label("Exclude look-alike characters (0, O, 1, l)")
                    .on_toggle(|value| Message::Generator(Event::Toggle(Toggle::Ambiguous, value))),
            );
    }
    if let Some(message) =
        app.generator
            .input_error(app.passphrase, &app.generator_length, &app.words)
    {
        form = form.push(error(message));
    }
    form = form.push(disclosure(
        "Generation preferences & strength checker",
        app.ui.generator_advanced,
        presentation::Disclosure::Generator,
        !app.busy,
    ));
    if app.ui.generator_advanced {
        if !app.passphrase && app.generator.symbols {
            form = form.push(label("Allowed symbols")).push(
                text_input("Allowed symbol characters", &app.generator.symbol_set)
                    .padding(12)
                    .on_input(|value| Message::Generator(Event::Symbols(value))),
            );
        }
        form = form
            .push(label("Show strength and statistics"))
            .push(
                pick_list(Policy::ALL.as_slice(), Some(app.generator.stats), |value| {
                    Message::Generator(Event::Stats(value))
                })
                .padding(12)
                .width(Fill),
            )
            .push(label("Copy automatically after generation"))
            .push(
                pick_list(Policy::ALL.as_slice(), Some(app.generator.copy), |value| {
                    Message::Generator(Event::Copy(value))
                })
                .padding(12)
                .width(Fill),
            )
            .push(label(
                "Clipboard timeout override (0–255 seconds; blank uses Settings)",
            ))
            .push(
                text_input("Use saved setting", &app.generator.copy_timeout)
                    .padding(12)
                    .on_input(|value| Message::Generator(Event::CopyTimeout(value))),
            )
            .push(rule::horizontal(1))
            .push(text("Check an existing password").size(20))
            .push(
                text_input("Password to assess locally", app.generator.check.expose())
                    .secure(true)
                    .padding(12)
                    .on_input(|value: String| Message::Generator(Event::Check(value.into())))
                    .on_submit(Message::Generator(Event::Evaluate)),
            )
            .push(action(
                "Check strength",
                Message::Generator(Event::Evaluate),
                !app.busy && !app.generator.check.is_empty(),
            ));
        if !app.generator.assessment.is_empty() {
            form = form.push(text(&app.generator.assessment).size(14));
        }
    }
    let policy = app.generator.generation_policy(&app.conf);
    if let Err(message) = &policy {
        form = form.push(error(message.clone()));
    }
    let footer = row![
        primary(
            if app.generated.is_empty() {
                "Generate"
            } else {
                "Generate another"
            },
            Message::Generate,
            !app.busy
                && policy.is_ok()
                && app
                    .generator
                    .input_error(app.passphrase, &app.generator_length, &app.words)
                    .is_none()
        ),
        text("Generated locally on this device").size(14),
    ]
    .spacing(12)
    .align_y(Alignment::Center)
    .wrap();
    let mut body = column![
        text("Password generator").size(25),
        text("Create a unique secret for every account.").size(15)
    ]
    .spacing(14);
    if !app.generated.is_empty() {
        body = body.push(panel(column![
            text("Your generated secret").size(18),
            text_input("Generated value", app.generated.expose()).secure(!app.show_generated).padding(12),
            row![primary("Copy", Message::CopyGenerated, !app.busy && app.generator.copy_timeout(&app.conf).is_ok_and(|timeout| timeout > 0)),
                checkbox(app.show_generated).label("Show value").on_toggle(Message::ShowGenerated)].spacing(16).wrap(),
            text("Cleared from this screen after 60 seconds. Stored only when you save it in an item.").size(14),
        ].spacing(12)));
        if !app.generated_stats.is_empty() {
            body = body.push(text(&app.generated_stats).size(14));
        }
    }
    body = body.push(form);
    container(
        panel(
            column![
                scrollable(body)
                    .id("generator-form")
                    .height(Fill)
                    .spacing(10),
                rule::horizontal(1),
                footer,
            ]
            .spacing(12),
        )
        .max_width(700)
        .height(Fill),
    )
    .center_x(Fill)
    .height(Fill)
    .into()
}

fn settings(app: &App) -> Element<'_, Message> {
    use password_manager::config::Appearance;
    use presentation::SettingsSection;
    let field = |name: &'static str, value: &str, field: SettingsField| {
        let mut control = column![
            label(name),
            text_input("", value).padding(12).on_input_maybe(
                (!app.busy).then_some(move |value| Message::SettingChanged(field, value))
            )
        ]
        .spacing(6);
        if let Some(message) = app.settings.field_error(field, value) {
            control = control.push(error(message));
        }
        control
    };
    let mut form = column![].spacing(14);
    form = match app.ui.settings_section {
        SettingsSection::Appearance => form
            .push(
                column![
                    label("Color theme"),
                    pick_list(
                        [
                            Appearance::Dark,
                            Appearance::Light,
                            Appearance::HighContrast
                        ],
                        Some(app.settings.appearance),
                        Message::Appearance
                    )
                    .padding(10)
                    .width(Fill)
                ]
                .spacing(6),
            )
            .push(
                column![
                    label("Text and control size"),
                    pick_list(
                        [100_u16, 115, 130].map(presentation::ScaleChoice),
                        Some(presentation::ScaleChoice(app.settings.scale)),
                        |choice| Message::InterfaceScale(choice.0)
                    )
                    .padding(10)
                    .width(Fill)
                ]
                .spacing(6),
            )
            .push(text("Changes preview immediately. Save settings to keep them.").size(14)),
        SettingsSection::Passwords => form
            .push(field(
                "Default password length (1–255)",
                &app.settings.length,
                SettingsField::Length,
            ))
            .push(
                checkbox(app.settings.stats)
                    .label("Show generated password strength and statistics")
                    .on_toggle(|value| {
                        Message::SettingToggled(SettingsToggle::GeneratorStats, value)
                    }),
            )
            .push(
                checkbox(app.settings.generator_copy)
                    .label("Copy generated passwords automatically")
                    .on_toggle(|value| {
                        Message::SettingToggled(SettingsToggle::GeneratorCopy, value)
                    }),
            )
            .push(
                checkbox(app.settings.password_copy)
                    .label("Copy newly added login passwords automatically")
                    .on_toggle(|value| {
                        Message::SettingToggled(SettingsToggle::PasswordCopy, value)
                    }),
            ),
        SettingsSection::Security => {
            let mut choices = vec![vault_names::Choice {
                id: String::new(),
                label: "Automatic selection".into(),
            }];
            choices.extend(app.vault_choices());
            if !app.settings.default_vault.is_empty()
                && !choices
                    .iter()
                    .any(|choice| choice.id == app.settings.default_vault)
            {
                choices.push(vault_names::Choice {
                    id: app.settings.default_vault.clone(),
                    label: "Unavailable vault".into(),
                });
            }
            let selected = choices
                .iter()
                .find(|choice| choice.id == app.settings.default_vault)
                .cloned();
            form.push(field(
                "Clear clipboard after seconds (0 disables copying)",
                &app.settings.clipboard_timeout,
                SettingsField::ClipboardTimeout,
            ))
            .push(field(
                "Lock after inactivity (15m, 1h, seconds; 0 disables)",
                &app.settings.unlock_timeout,
                SettingsField::UnlockTimeout,
            ))
            .push(label("Default vault"))
            .push(
                pick_list(choices, selected, |choice: vault_names::Choice| {
                    Message::SettingChanged(SettingsField::DefaultVault, choice.id)
                })
                .width(Fill)
                .padding(12),
            )
            .push(text("The lock timeout applies on the next unlock.").size(14))
            .push(action(
                "Vault credentials & security tools",
                Message::OpenTools(workflows::Section::Security),
                !app.busy,
            ))
        }
        SettingsSection::Recovery => form
            .push(field(
                "Previous passwords kept per item (0 disables history)",
                &app.settings.history_limit,
                SettingsField::HistoryLimit,
            ))
            .push(field(
                "Purge trash after days (0 keeps it indefinitely)",
                &app.settings.trash_retention,
                SettingsField::TrashRetention,
            ))
            .push(text("Restart the local service after changing recovery settings.").size(14))
            .push(action(
                "Open recovery tools",
                Message::OpenTools(workflows::Section::Overview),
                !app.busy,
            ))
            .push(action(
                "Import, export & backups",
                Message::OpenTools(workflows::Section::Overview),
                !app.busy,
            )),
        SettingsSection::Connection => {
            form = form.push(text(if app.running { "The local service is running. It keeps your vault available to the CLI and browser extension when this window closes." } else { "The local service is stopped." }).size(15));
            form = if app.running {
                form.push(
                    action(
                        "Stop local service…",
                        Message::ConfirmStop(true),
                        !app.busy && app.pending.is_none(),
                    )
                    .style(button_style::danger),
                )
            } else {
                form.push(primary("Start local service", Message::Connect, !app.busy))
            };
            if app.ui.confirm_stop {
                form = form.push(panel(column![
                    text("Stop the local service?").size(18),
                    text("This locks the vault, discards any open item draft, and disconnects the browser extension and CLI until you start it again.").size(14),
                    row![primary("Keep running", Message::ConfirmStop(false), !app.busy), action("Stop service", Message::Stop, !app.busy && app.pending.is_none()).style(button_style::danger)].spacing(8).wrap(),
                ].spacing(12)));
            }
            form.push(rule::horizontal(1))
                .push(field(
                    "Saved service port (1–65535)",
                    &app.settings.server_port,
                    SettingsField::ServerPort,
                ))
                .push(text("Stop the service before changing its saved port.").size(14))
                .push(connection_controls(app))
                .push(action(
                    "Browser integration",
                    Message::OpenTools(workflows::Section::Browser),
                    !app.busy,
                ))
        }
    };
    if app.ui.settings_section == SettingsSection::Security && app.vault.is_some() {
        form = form
            .push(rule::horizontal(1))
            .push(text("Vault name on this device").size(19))
            .push(
                text_input("Personal or Work", &app.ui.vault_name)
                    .padding(12)
                    .on_input(Message::VaultName),
            )
            .push(action(
                "Save vault name",
                Message::RenameVault,
                app.writes_allowed() && !app.ui.vault_name.trim().is_empty(),
            ));
    }
    let mut footer = column![].spacing(10);
    if let Err(message) = app.settings.changes() {
        footer = footer.push(error(message));
    }
    if app.confirm_reset_settings {
        footer = footer
            .push(text("Reset all settings, including appearance, to their defaults?").size(15))
            .push(
                row![
                    primary("Keep settings", Message::CancelResetSettings, !app.busy),
                    action("Reset settings", Message::ConfirmResetSettings, !app.busy)
                        .style(button_style::danger)
                ]
                .spacing(8)
                .wrap(),
            );
    } else {
        footer = footer.push(
            row![
                primary(
                    "Save settings",
                    Message::SaveSettings,
                    !app.busy && app.settings.is_dirty() && app.settings.changes().is_ok()
                ),
                action("Reset to defaults…", Message::ResetSettings, !app.busy)
            ]
            .spacing(8)
            .wrap(),
        );
    }
    footer = footer.push(
        text(if app.settings.is_dirty() {
            "Unsaved settings · Ctrl/Cmd+S to save"
        } else {
            "All settings saved"
        })
        .size(14),
    );
    let options = column![
        row![
            pick_list(
                SettingsSection::ALL,
                Some(app.ui.settings_section),
                Message::SettingsSection
            )
            .width(Fill)
            .padding(10),
            action("Refresh", Message::ReloadSettings, !app.busy),
        ]
        .spacing(10)
        .align_y(Alignment::Center),
        rule::horizontal(1),
        form,
    ]
    .spacing(14);
    container(
        panel(
            column![
                scrollable(options).id("page-form").height(Fill).spacing(10),
                rule::horizontal(1),
                footer,
            ]
            .spacing(12),
        )
        .max_width(800)
        .height(Fill),
    )
    .center_x(Fill)
    .height(Fill)
    .into()
}
