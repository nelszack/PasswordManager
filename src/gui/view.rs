use super::*;
use crate::gui::styles::{
    action, error, label, panel, primary, quiet_button, quiet_danger, tab_style,
};
use crate::gui::widgets::{button, checkbox, pick_list, scrollable, text_input};
use iced::widget::button as button_style;
use iced::{
    Alignment, Fill, Length,
    widget::{Column, column, container, row, rule, text, text_editor},
};

/// Four-segment strength bar with a text rating, so color is never the only cue.
pub(super) fn strength_meter<'a>((score, rating): model::Strength) -> Element<'a, Message> {
    let filled = usize::from(score.max(1));
    let mut bars = row![].spacing(4);
    for index in 0..4 {
        bars = bars.push(
            container(text(""))
                .width(Length::Fixed(36.0))
                .height(Length::Fixed(6.0))
                .style(move |theme: &Theme| {
                    let palette = theme.extended_palette();
                    let color = if index >= filled {
                        palette.background.strong.color
                    } else if score <= 1 {
                        palette.danger.base.color
                    } else if score == 2 {
                        palette.warning.base.color
                    } else {
                        palette.success.base.color
                    };
                    container::Style {
                        background: Some(color.into()),
                        border: iced::Border {
                            radius: 3.0.into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    }
                }),
        );
    }
    row![bars, text(format!("Strength: {rating}")).size(13)]
        .spacing(10)
        .align_y(Alignment::Center)
        .into()
}

/// Circular initial badge that makes list rows scannable.
fn avatar<'a>(name: &str, selected: bool) -> Element<'a, Message> {
    let initial = name
        .chars()
        .find(|c| c.is_alphanumeric())
        .map(|c| c.to_uppercase().collect::<String>())
        .unwrap_or_else(|| "•".into());
    container(text(initial).size(16))
        .width(Length::Fixed(36.0))
        .height(Length::Fixed(36.0))
        .center_x(Length::Fixed(36.0))
        .center_y(Length::Fixed(36.0))
        .style(move |theme: &Theme| {
            let palette = theme.extended_palette();
            let pair = if selected {
                palette.primary.base
            } else {
                palette.primary.weak
            };
            container::Style {
                background: Some(pair.color.into()),
                text_color: Some(pair.text),
                border: iced::Border {
                    radius: 18.0.into(),
                    ..Default::default()
                },
                ..Default::default()
            }
        })
        .into()
}

fn disclosure<'a>(
    title: &'a str,
    expanded: bool,
    section: presentation::Disclosure,
    enabled: bool,
) -> Element<'a, Message> {
    // The title stays in the name, so two open sections never share a label.
    let label = if expanded {
        let mut chars = title.chars();
        let lower = chars.next().map_or_else(String::new, |first| {
            first.to_lowercase().collect::<String>() + chars.as_str()
        });
        format!("Hide {lower}")
    } else {
        title.to_owned()
    };
    crate::gui::styles::text_action(label, Message::Disclosure(section), enabled).into()
}

fn navigation(app: &App) -> Element<'_, Message> {
    let mut tabs = row![].spacing(8);
    use crate::gui::icon_chars as i;
    for (title, tab, glyph) in [
        ("Vault", Tab::Vault, i::SHIELD),
        ("Generator", Tab::Generator, i::PASSWORD),
        ("Tools", Tab::Tools, i::BUILD),
        ("Settings", Tab::Settings, i::SETTINGS),
    ] {
        let selected = app.tab == tab;
        tabs = tabs.push(
            crate::gui::styles::icon_button(glyph, title, Message::Tab(tab), !app.busy())
                .selected(selected)
                .padding(if app.compact() { [9, 10] } else { [11, 16] })
                .style(tab_style(selected)),
        );
    }
    tabs.wrap().into()
}

pub(super) fn view(app: &App) -> Element<'_, Message> {
    let status = if !app.connection.running {
        "Offline".to_owned()
    } else if app.connection.session.is_some() {
        if let Some((id, _)) = app
            .ui
            .active_vault
            .as_ref()
            .filter(|(_, session)| app.connection.session.as_ref() == Some(session))
        {
            let name = app.names.label(id, &app.connection.vaults);
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
        crate::gui::styles::tip(
            action(
                "Help",
                Message::Disclosure(presentation::Disclosure::Shortcuts),
                !app.busy()
            )
            .padding(if app.compact() { [9, 10] } else { [11, 14] }),
            format!(
                "Help and shortcuts ({}+/)",
                crate::gui::styles::command_key()
            )
        ),
        crate::gui::styles::tip(
            action(
                if app.compact() { "Lock" } else { "Lock vault" },
                Message::Lock,
                app.connection.running && app.connection.session.is_some()
            )
            .padding(if app.compact() { [9, 10] } else { [11, 14] }),
            format!("{}+L", crate::gui::styles::command_key())
        ),
    ]
    .spacing(8)
    .align_y(Alignment::Center);
    // Keep dynamic banners inside a stable child so edits do not replace the
    // main content's widget state (focus, cursor, and scroll positions).
    let mut chrome = column![navigation(app)].spacing(12);
    if app.editor.as_ref().is_some_and(|draft| draft.dirty) {
        chrome = chrome.push(text("Unsaved item changes · Locking discards this draft.").size(13));
    }
    if app.ui.confirm_close.is_some() {
        chrome = chrome.push(panel(
            column![
                text("Close this window?").size(20),
                text(
                    "Unsaved item and settings changes will be discarded. A running operation may \
                     still finish; check its outcome before retrying. The local service stays \
                     running."
                )
                .size(14),
                row![
                    primary("Keep window open", Message::CancelClose, true).id("keep-window-open"),
                    action("Close and discard changes", Message::ConfirmClose, true)
                        .style(quiet_danger)
                ]
                .spacing(8)
                .wrap()
            ]
            .spacing(10),
        ));
    }
    if app.ui.confirm_lock_close.is_some() {
        chrome = chrome.push(panel(
            column![
                text("Lock your vault before closing?").size(20),
                text(
                    "If you keep it unlocked, the browser extension and the pm command can still \
                     use it until it locks after inactivity. Choose a default in Settings → \
                     Security."
                )
                .size(14),
                row![
                    primary("Lock and close", Message::CloseWindow(true), true)
                        .id("lock-and-close"),
                    action("Keep unlocked and close", Message::CloseWindow(false), true),
                    action("Cancel", Message::CancelClose, true),
                ]
                .spacing(8)
                .wrap()
            ]
            .spacing(10),
        ));
    }
    if app.editor.deferred().is_some() {
        chrome = chrome.push(panel(
            column![
                text("Keep your unsaved changes?").size(18),
                text(
                    "Your item has not been saved. Keep editing, or discard the draft to continue."
                )
                .size(14),
                row![
                    primary("Keep editing", Message::KeepEditing, !app.busy()).id("keep-editing"),
                    action("Discard changes", Message::Discard, !app.busy())
                        .style(button_style::danger)
                ]
                .spacing(8)
                .wrap(),
            ]
            .spacing(10),
        ));
    }
    if let Some(id) = app.recovery.id() {
        let mut recovery = column![
            text("Review the last change before continuing").size(17),
            text(
                "The result of a previous change is uncertain. Inspect the vault before allowing \
                 new changes."
            )
            .size(14),
            text(format!("Operation {id}")).size(14),
            primary(
                "Check last change",
                Message::Reconcile,
                !app.busy() && app.connection.running
            ),
        ]
        .spacing(8);
        if app.recovery.reviewed() {
            recovery = recovery.push(action(
                "I inspected the vault; allow new changes",
                Message::Acknowledge,
                !app.busy(),
            ));
        }
        chrome = chrome.push(scrollable(panel(recovery)).height(Length::Fixed(150.0)));
    }
    if let Some(warning) = &app.warning {
        chrome = chrome.push(panel(text(warning).size(14).style(text::danger)));
    }
    if let Some(notice) = &app.ui.format_notice {
        chrome = chrome.push(panel(
            row![
                text(notice).size(14).width(Fill),
                action("Got it", Message::DismissFormatNotice, true),
            ]
            .spacing(8)
            .align_y(Alignment::Center),
        ));
    }
    for request in &app.ui.ssh_requests {
        chrome =
            chrome.push(panel(
                column![
                text("SSH key requested").size(17),
                text(format!(
                    "A program wants to sign in to {} with “{}”. Allow it only if you just started \
                     that connection.",
                    request.host, request.key
                ))
                .size(14),
                row![
                    primary(
                        "Allow once",
                        Message::SshDecision(request.id.clone(), true),
                        !app.busy()
                    ),
                    action("Refuse", Message::SshDecision(request.id.clone(), false), !app.busy())
                        .style(quiet_danger),
                ]
                .spacing(8)
                .wrap(),
            ]
                .spacing(8),
            ));
    }
    if let Some(request) = app.ui.passkey_requests.first() {
        let site = request
            .site
            .strip_prefix("https://")
            .unwrap_or(&request.site);
        let waiting = app.ui.passkey_requests.len() - 1;
        chrome = chrome.push(panel(
            column![
                text("Confirm it's you").size(17),
                text(format!(
                    "{site} asked your browser for a passkey and wants proof that it is you. \
                     Confirm only if you just did this in your browser.{}",
                    if waiting > 0 {
                        format!(" {waiting} more waiting.")
                    } else {
                        String::new()
                    }
                ))
                .size(14),
                text_input(
                    if app.ui.passkey_pin {
                        "Master password or passkey PIN"
                    } else {
                        "Master password"
                    },
                    app.ui.passkey_secret.expose(),
                )
                .id("passkey-secret")
                .secure(true)
                .padding(12)
                .on_input(|value: String| Message::PasskeySecret(value.into()))
                .on_submit(Message::PasskeyDecision(request.id.clone(), true)),
                row![
                    primary(
                        "Confirm",
                        Message::PasskeyDecision(request.id.clone(), true),
                        !app.busy()
                    ),
                    action(
                        "Refuse",
                        Message::PasskeyDecision(request.id.clone(), false),
                        !app.busy()
                    )
                    .style(quiet_danger),
                ]
                .spacing(8)
                .wrap(),
            ]
            .spacing(8),
        ));
    }
    if let Some(target) = app.workspace.duo.watch.as_ref() {
        chrome = chrome.push(
            row![
                text(format!("Watching Duo · {}", target.choice))
                    .size(14)
                    .width(Fill),
                action(
                    "Review requests",
                    Message::OpenToolItem(target.choice.id),
                    !app.busy()
                ),
                action(
                    "Stop watching",
                    Message::Workflow(workflows::Event::Toggle(workflows::Toggle::WatchDuo, false)),
                    !app.busy()
                ),
            ]
            .spacing(8)
            .wrap(),
        );
    }
    let mut page = column![header, chrome].spacing(12);
    let content = if app.ui.shortcuts {
        shortcuts()
    } else {
        match app.tab {
            Tab::Vault if !app.connection.running => stopped(app),
            Tab::Vault if app.connection.session.is_none() => unlock(app),
            Tab::Vault => vault(app),
            Tab::Generator => generator(app),
            Tab::Settings => settings(app),
            Tab::Tools => app.workspace.view(app),
        }
    };
    let short = app.ui.height < 460.0 || (app.recovery.id().is_some() && app.ui.height < 680.0);
    if short {
        // At very small heights, scroll the entire page, including its chrome.
        // Each inner pane retains a useful viewport instead of collapsing.
        page = page.push(container(content).width(Fill).height(520));
    } else {
        page = page.push(container(content).width(Fill).height(Fill));
    }
    if app.editor.is_some() && app.tab != Tab::Vault {
        page = page.push(action(
            "Return to item draft",
            Message::Tab(Tab::Vault),
            !app.busy(),
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
    let mut keys = column![text("Help").size(25)].spacing(16);
    // Common tasks, each with a direct way to start it.
    for (title, body, button, message) in [
        (
            "Use the browser extension",
            "Fill and save logins in Chrome, Chromium, Helium, or Firefox. Turn on browser \
             integration once, then reload the extension.",
            "Set up browser integration",
            Message::OpenTools(workflows::Section::Browser),
        ),
        (
            "Keep a backup",
            "An encrypted backup restores everything, including history and deleted items. It \
             needs the backup password you choose.",
            "Create a backup",
            Message::OpenFileTool(workflows::FileOperation::Backup),
        ),
        (
            "Use the vault on other devices",
            "Sync stores only encrypted copies on your own server. Connect with the server address \
             and a device credential from whoever runs it.",
            "Sync settings",
            Message::OpenSettings(presentation::SettingsSection::Sync),
        ),
        (
            "Recover something",
            "Deleted items stay in the trash until you erase them, and each item keeps its \
             previous passwords.",
            "Deleted items",
            Message::OpenTools(workflows::Section::Trash),
        ),
        (
            "Forgot the master password?",
            "There is no reset. A key-file vault opens with its key file, and an encrypted backup \
             opens with its own backup password.",
            "Restore a backup",
            Message::OpenFileTool(workflows::FileOperation::Restore),
        ),
    ] {
        keys = keys.push(
            column![
                text(title).size(18),
                text(body).size(14),
                action(button, message, true).padding([7, 10]),
            ]
            .spacing(6),
        );
    }
    keys = keys
        .push(rule::horizontal(1))
        .push(text("Keyboard shortcuts").size(22))
        .push(
            text("Use Tab and Shift+Tab to move between controls. Focus scrolls into view.")
                .size(15),
        );
    for (key, description) in [
        ("F", "Search your items"),
        ("N", "Add an item"),
        ("S", "Save the current item or settings"),
        ("E", "Edit the selected item"),
        ("R", "Refresh your items"),
        ("Shift+C", "Copy username"),
        ("Shift+P", "Copy password (or the item's main secret)"),
        ("Shift+T", "Copy the one-time code"),
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
    keys = keys.push(
        text(
            "Up and Down select the previous or next item, also while typing a search. Enter / \
             Space activates a control. Focus a message pane and use Page Up/Page Down to \
             scroll it. Escape hides revealed secrets.",
        )
        .size(14),
    );
    panel(
        column![
            scrollable(keys).height(Fill),
            action(
                "Close help",
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
    let progress;
    let message = if app.busy() {
        progress = format!(
            "{} · {}s elapsed",
            if app.ui.progress.is_empty() {
                "Working…"
            } else {
                &app.ui.progress
            },
            app.ui
                .progress_started
                .map(|start| start.elapsed().as_secs())
                .unwrap_or(0)
        );
        progress.as_str()
    } else if app.notice.is_empty() {
        "Ready"
    } else {
        &app.notice
    };
    let mut content = column![].spacing(3);
    if app.busy() {
        content = content.push(text("Operation in progress").size(14));
    }
    if app.ui.notice_error {
        content = content.push(text("Needs attention").size(14));
    }
    content = content.push(text(message.to_owned()).size(14));
    // A shape as well as a colour: a warning sign for problems, an info mark for notices.
    let mut line = row![];
    if !app.busy() && !app.notice.is_empty() {
        line = line.push(crate::gui::styles::icon(if app.ui.notice_error {
            crate::gui::icon_chars::WARNING
        } else {
            crate::gui::icon_chars::INFO
        }));
    }
    let mut line = line
        .push(
            container(crate::gui::widgets::keyboard_scrollable(
                content,
                "notice",
                (!app.busy() && !app.notice.is_empty()).then_some((message, app.ui.notice_error)),
            ))
            .width(Fill)
            .height(Fill),
        )
        .spacing(10)
        .align_y(Alignment::Center);
    if app
        .ui
        .undo_trash
        .as_ref()
        .is_some_and(|(_, session)| app.connection.session.as_ref() == Some(session))
        && app.tab == Tab::Vault
        && app.editor.is_none()
    {
        line = line.push(action(
            "Undo deletion",
            Message::UndoDelete,
            !app.busy() && app.recovery.id().is_none(),
        ));
    }
    if !app.notice.is_empty() {
        line = line.push(action("Dismiss", Message::DismissNotice, !app.busy()));
    }
    // Errors and longer guidance get room to be read without scrolling.
    let tall = app.ui.notice_error || app.notice.chars().count() > 110;
    container(line)
        .padding([4, 8])
        .height(if tall { 104 } else { 52 })
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
        .connection
        .connection_port
        .trim()
        .parse::<u16>()
        .is_ok_and(|port| port > 0);
    let mut controls = column![
        label("Temporary connection port (1–65535)"),
        row![
            text_input("Port", &app.connection.connection_port)
                .padding(10)
                .on_input_maybe((!app.busy()).then_some(Message::ConnectionPort))
                .on_submit_maybe((!app.busy() && valid_port).then_some(Message::UseConnectionPort)),
            action(
                "Connect",
                Message::UseConnectionPort,
                !app.busy() && valid_port
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
    let mut form = column![
        text("Open your vault").size(27),
        text(
            "Password Manager runs a small background helper that keeps your vault and talks to \
             the browser extension. It isn't running right now."
        )
        .size(15),
        primary("Start and continue", Message::Connect, !app.busy()),
        rule::horizontal(1),
        disclosure(
            "Troubleshooting",
            app.ui.troubleshooting,
            presentation::Disclosure::Troubleshooting,
            !app.busy(),
        ),
    ]
    .spacing(16);
    if app.ui.troubleshooting {
        form = form
            .push(text("Connect to a helper already running on another port").size(16))
            .push(connection_controls(app));
    }
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
    let enabled = !app.busy();
    if app.connection.vaults.is_empty() && !app.connection.creating {
        return container(
            container(
                scrollable(
                    panel(
                        column![
                            text("Your passwords. Your vault.").size(28),
                            text(
                                "Keep logins, notes, and other secrets together in an encrypted \
                                 vault on this device."
                            )
                            .size(16),
                            primary(
                                "Create your first vault",
                                Message::Creating(true),
                                app.writes_allowed()
                            ),
                            action(
                                "Import passwords",
                                Message::OpenFileTool(workflows::FileOperation::Import),
                                enabled
                            ),
                            action(
                                "Restore an encrypted backup",
                                Message::OpenFileTool(workflows::FileOperation::Restore),
                                enabled
                            ),
                            action(
                                "Download my vault from a sync server",
                                Message::OpenSettings(presentation::SettingsSection::Sync),
                                enabled
                            ),
                            rule::horizontal(1),
                            text("Already have a vault on this device?").size(14),
                            action("Find existing vaults", Message::RefreshVaults, enabled),
                        ]
                        .spacing(18),
                    )
                    .max_width(580),
                )
                .height(Fill),
            )
            .max_width(620),
        )
        .center_x(Fill)
        .height(Fill)
        .into();
    }
    let mut form = column![
        text(if app.connection.creating {
            "Create your vault"
        } else {
            "Welcome back"
        })
        .size(28),
        text(if app.connection.creating {
            "One master password protects everything in this vault."
        } else {
            "Unlock your vault to access your items."
        })
        .size(15),
    ]
    .spacing(14);
    if !app.connection.creating {
        let choices = app.vault_choices();
        let selected = choices
            .iter()
            .find(|choice| Some(&choice.id) == app.connection.vault.as_ref())
            .cloned();
        form = form.push(label("Vault")).push(
            pick_list(choices, selected, |choice: vault_names::Choice| {
                Message::Vault(choice.id)
            })
            .placeholder("Vault to unlock")
            .width(Fill)
            .padding(12),
        );
    }
    let using_key =
        !app.connection.creating && app.ui.unlock_advanced && !app.connection.key_path.is_empty();
    if app.connection.creating {
        form = form.push(
            column![
                label("Vault name"),
                text_input("Personal or Work", &app.ui.vault_name)
                    .accessibility_label("Vault name")
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
                row![
                    text_input("Enter master password", app.connection.master.expose())
                        .id("master-password")
                        .accessibility_label("Master password")
                        .secure(!app.ui.master_visible)
                        .padding(12)
                        .width(Fill)
                        .on_input_maybe(
                            enabled.then_some(|value: String| Message::Master(value.into()))
                        )
                        .on_submit_maybe(
                            (enabled && !app.connection.creating).then_some(Message::Unlock)
                        ),
                    action(
                        if app.ui.master_visible {
                            "Hide"
                        } else {
                            "Show"
                        },
                        Message::RevealMaster(!app.ui.master_visible),
                        enabled
                    )
                    .padding([9, 12]),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            ]
            .spacing(6),
        );
    }
    if let Some(message) = &app.ui.unlock_error {
        form = form.push(error(message.clone()));
    }
    if app.connection.creating {
        if let Some(strength) = app.ui.master_strength {
            form = form.push(strength_meter(strength));
        }
        form = form.push(
            row![
                text("Use 14+ characters, such as several unrelated words.")
                    .size(14)
                    .width(Fill),
                action("Suggest a passphrase", Message::SuggestMaster, enabled),
            ]
            .spacing(10)
            .align_y(Alignment::Center)
            .wrap(),
        );
        if let Some(phrase) = &app.ui.suggested_master {
            form = form.push(
                panel(
                    column![
                        text("Your new master password").size(14),
                        text(phrase.expose()).size(20),
                        text("Write it down and keep it somewhere safe before you continue.")
                            .size(13),
                    ]
                    .spacing(6),
                )
                .width(Fill),
            );
        }
        form = form
            .push(
                text(
                    "Keep this password somewhere safe. It cannot be reset; a backup still needs \
                     its original password or key file.",
                )
                .size(14),
            )
            .push(
                column![
                    label("Confirm master password"),
                    text_input("Enter it again", app.connection.confirmation.expose())
                        .accessibility_label("Confirm master password")
                        .secure(!app.ui.master_visible)
                        .padding(12)
                        .on_input_maybe(
                            enabled.then_some(|value: String| Message::ConfirmMaster(value.into()))
                        )
                        .on_submit_maybe(
                            (app.writes_allowed()
                                && app.connection.master == app.connection.confirmation
                                && !app.connection.master.is_empty()
                                && app.ui.master_error.is_none()
                                && vault_names::validate_name(&app.ui.vault_name).is_ok())
                            .then_some(Message::Create)
                        )
                ]
                .spacing(6),
            );
        if !app.connection.master.is_empty()
            && let Some(message) = app.ui.master_error
        {
            form = form.push(error(message));
        }
        if !app.connection.confirmation.is_empty()
            && app.connection.master != app.connection.confirmation
        {
            form = form.push(error("The passwords do not match yet."));
        }
    } else {
        form = form
            .push(
                text(
                    "Forgot your password? There is no reset. Use the key file for a key-based \
                     vault, or restore a backup using its original credentials.",
                )
                .size(14),
            )
            .push(action(
                "Restore an encrypted backup",
                Message::OpenFileTool(workflows::FileOperation::Restore),
                enabled,
            ));
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
                    text_input("15m", &app.connection.unlock_timeout)
                        .accessibility_label("Lock after inactivity")
                        .padding(12)
                        .on_input(Message::UnlockTimeout),
                );
            if let Err(message) =
                password_manager::config::parse_duration(&app.connection.unlock_timeout)
            {
                form = form.push(error(message));
            }
            if let Some(id) = &app.connection.vault {
                form = form
                    .push(label("Vault file (advanced)"))
                    .push(text(id).size(14));
            }
            form = form
                .push(label("External key file (optional)"))
                .push(
                    row![
                        text_input(
                            "Absolute path to your key file",
                            app.connection.key_path.expose()
                        )
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
    let actions = if app.connection.creating {
        row![
            primary(
                "Create vault",
                Message::Create,
                app.writes_allowed()
                    && app.connection.master == app.connection.confirmation
                    && !app.connection.master.is_empty()
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
            enabled && (!app.connection.master.is_empty() || using_key)
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
    let entries = item_entries(app);
    let count = app.matching_items().len();
    let window = presentation::Page::items(app.ui.item_page, count);
    let (pages, page) = (window.pages, window.index);
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
    let mut sidebar = column![
        row![
            text("Your items").size(22).width(Fill),
            crate::gui::styles::tip(
                primary(
                    "Add item",
                    Message::Navigate(Navigate::New),
                    app.writes_allowed()
                ),
                format!("{}+N", crate::gui::styles::command_key())
            )
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        row![
            text_input("Search items", &app.query)
                .accessibility_label("Search by name, username, website, or tag")
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
            .placeholder("Filter item type")
            .width(135)
            .padding(10),
        ]
        .spacing(8),
        tag_filters(app),
        row![
            text(if app.compact() {
                format!("{count} / {}", app.items.len())
            } else {
                format!("{count} of {} items", app.items.len())
            })
            .size(13)
            .width(Fill),
            pick_list(
                ["A–Z", "Z–A"],
                Some(if app.ui.reverse_items {
                    "Z–A"
                } else {
                    "A–Z"
                }),
                |value| Message::SortItems(value == "Z–A")
            )
            .placeholder("Sort items")
            .padding(8)
            .width(85),
            action(
                "Advanced search",
                Message::OpenTools(workflows::Section::Search),
                !app.busy()
            )
            .padding([7, 8]),
            action(
                if app.ui.selecting { "Done" } else { "Select" },
                Message::ToggleSelecting,
                !app.busy() && !app.items.is_empty()
            )
            .padding([7, 8]),
        ]
        .spacing(6)
        .align_y(Alignment::Center)
        .wrap(),
        bulk_bar(app),
        scrollable(entries).id("item-list").spacing(8).height(Fill),
    ]
    .spacing(10)
    .height(Fill);
    if pages > 1 {
        sidebar = item_pager(sidebar, app, page, pages);
    }
    let detail = if let Some(draft) = app.editor.as_ref() {
        editor(app, draft)
    } else if let Some(item) = &app.item {
        details(app, item)
    } else {
        vault_welcome(app)
    };
    let panes: Element<'_, Message> = if app.compact() {
        if app.editor.is_some() {
            detail
        } else if app.item.is_some() {
            column![
                action(
                    "Back to items",
                    Message::Navigate(Navigate::Close),
                    !app.busy()
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
            // Wider windows give names, usernames, and tags more room.
            sidebar.width((app.ui.width * 0.32).clamp(310.0, 460.0)),
            container(detail).width(Fill).height(Fill)
        ]
        .spacing(20)
        .height(Fill)
        .into()
    };
    let body = column![].spacing(12).height(Fill);
    body.push(panes).into()
}

/// Selection mode: what is chosen, and what to do with it.
fn bulk_bar(app: &App) -> Element<'_, Message> {
    if !app.ui.selecting {
        return column![].into();
    }
    let count = app.ui.selected.len();
    let enabled = app.writes_allowed() && count > 0;
    let mut bar = column![
        row![
            text(match count {
                0 => "Choose items to change.".to_owned(),
                1 => "1 item selected".to_owned(),
                n => format!("{n} items selected"),
            })
            .size(14)
            .width(Fill),
            action("Select all shown", Message::SelectAllShown, !app.busy()).padding([6, 8]),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
        row![
            crate::gui::styles::icon_button(
                crate::gui::icon_chars::STAR,
                "Favorite",
                Message::BulkStart(BulkOp::Favorite(true)),
                enabled
            )
            .padding([6, 8]),
            crate::gui::styles::icon_button(
                crate::gui::icon_chars::STAR_BORDER,
                "Unfavorite",
                Message::BulkStart(BulkOp::Favorite(false)),
                enabled
            )
            .padding([6, 8]),
            action("Move to trash…", Message::BulkStart(BulkOp::Trash), enabled)
                .style(quiet_danger)
                .padding([6, 8]),
        ]
        .spacing(6)
        .wrap(),
        row![
            text_input("Tag to add", &app.ui.bulk_tag)
                .accessibility_label("Tag to add to the selected items")
                .padding(8)
                .width(Fill)
                .on_input(Message::BulkTag)
                .on_submit_maybe(enabled.then_some(Message::BulkStart(BulkOp::Tag(String::new())))),
            action(
                "Add tag",
                Message::BulkStart(BulkOp::Tag(String::new())),
                enabled && !app.ui.bulk_tag.trim().is_empty()
            )
            .padding([6, 8]),
        ]
        .spacing(6)
        .align_y(Alignment::Center),
    ]
    .spacing(6);
    if app.ui.bulk_confirm {
        // Name what will move, so the confirmation is reviewable.
        let names: Vec<&str> = app
            .items
            .iter()
            .filter(|item| app.ui.selected.contains(&item.id))
            .map(|item| item.name.as_str())
            .collect();
        let shown = names.iter().take(5).copied().collect::<Vec<_>>().join(", ");
        let more = names.len().saturating_sub(5);
        bar = bar.push(panel(
            column![
                text(format!(
                    "Move {} to encrypted trash? {shown}{}",
                    if count == 1 {
                        "1 item".to_owned()
                    } else {
                        format!("{count} items")
                    },
                    if more > 0 {
                        format!(", and {more} more")
                    } else {
                        String::new()
                    }
                ))
                .size(14),
                row![
                    action("Cancel", Message::BulkCancel, true),
                    action("Move to trash", Message::BulkConfirm, app.writes_allowed())
                        .id("bulk-confirm")
                        .style(button_style::danger),
                ]
                .spacing(8),
            ]
            .spacing(8),
        ));
    }
    panel(bar).width(Fill).into()
}

/// Empty detail pane: first-run actions or a hint to select an item.
fn vault_welcome(app: &App) -> Element<'_, Message> {
    column![
        panel(
            column![
                text(if app.items.is_empty() {
                    "Add your first item"
                } else {
                    "Select an item"
                })
                .size(27),
                text(if app.items.is_empty() {
                    "Save a login, private note, card, or another secret. You can also import \
                         your passwords."
                } else {
                    "Choose an item to copy its sign-in details, open a website, or make a \
                         change."
                })
                .size(16),
                if app.items.is_empty() {
                    row![
                        primary(
                            "Add your first item",
                            Message::Navigate(Navigate::New),
                            app.writes_allowed()
                        ),
                        action(
                            "Import passwords",
                            Message::OpenFileTool(workflows::FileOperation::Import),
                            !app.busy()
                        )
                    ]
                } else {
                    row![
                        text(format!(
                            "{command}+F searches · Up/Down selects · {command}+N adds an item",
                            command = if cfg!(target_os = "macos") {
                                "Cmd"
                            } else {
                                "Ctrl"
                            }
                        ))
                        .size(14)
                    ]
                }
                .spacing(10)
                .wrap(),
            ]
            .spacing(16)
        )
        .width(Fill),
        panel(
            column![
                text("Keep your vault in good shape").size(19),
                text(format!(
                    "{} items · Encrypted on this device",
                    app.items.len()
                ))
                .size(14),
                row![
                    action(
                        "Check vault health",
                        Message::OpenTools(workflows::Section::Audit),
                        !app.busy()
                    ),
                    action(
                        "Create a backup",
                        Message::OpenFileTool(workflows::FileOperation::Backup),
                        !app.busy()
                    )
                ]
                .spacing(10)
                .wrap(),
            ]
            .spacing(12)
        )
        .width(Fill),
    ]
    .spacing(16)
    .width(Fill)
    .height(Fill)
    .into()
}

fn item_pager<'a>(
    mut sidebar: Column<'a, Message>,
    app: &'a App,
    page: usize,
    pages: usize,
) -> Column<'a, Message> {
    use presentation::ITEM_PAGE_SIZE as PAGE_SIZE;
    let shown_from = page * PAGE_SIZE + 1;
    sidebar = sidebar.push(
        row![
            action(
                format!("Previous {PAGE_SIZE}"),
                Message::ItemPage(page.saturating_sub(1)),
                !app.busy() && page > 0
            )
            .padding([7, 8]),
            text(format!(
                "Items {shown_from}–{} · page {} of {pages}",
                (shown_from + PAGE_SIZE - 1).min(app.matching_items().len()),
                page + 1
            ))
            .size(13)
            .width(Fill),
            action(
                format!("Next {PAGE_SIZE}"),
                Message::ItemPage((page + 1).min(pages - 1)),
                !app.busy() && page + 1 < pages
            )
            .padding([7, 8])
        ]
        .spacing(8)
        .align_y(Alignment::Center)
        .wrap(),
    );
    sidebar
}

/// Attachment names and sizes, with save/remove actions and an add button.
fn attachments_section<'a>(app: &'a App, item: &'a ItemDetail) -> Element<'a, Message> {
    let mut section = column![label("Attachments")].spacing(6);
    for (index, attachment) in item.attachments.iter().enumerate() {
        let size = match attachment.size {
            0..1024 => format!("{} B", attachment.size),
            1024..1_048_576 => format!("{:.1} KiB", attachment.size as f64 / 1024.0),
            _ => format!("{:.1} MiB", attachment.size as f64 / 1_048_576.0),
        };
        let mut controls = row![action(
            "Save as…",
            Message::SaveAttachment(index),
            !app.busy()
        )]
        .spacing(8);
        if app.remove_attachment.as_deref() == Some(attachment.name.as_str()) {
            controls = controls
                .push(
                    action(
                        "Confirm removal",
                        Message::ConfirmRemoveAttachment,
                        app.writes_allowed(),
                    )
                    .style(quiet_danger),
                )
                .push(action("Keep", Message::CancelRemoveAttachment, true));
        } else {
            controls = controls.push(
                action(
                    "Remove…",
                    Message::RemoveAttachment(index),
                    app.writes_allowed(),
                )
                .style(quiet_danger),
            );
        }
        section = section.push(
            column![
                text(format!("{} · {size}", attachment.name)).size(14),
                controls.wrap()
            ]
            .spacing(4),
        );
    }
    if item.attachments.is_empty() {
        section = section.push(text("No attachments").size(13));
    }
    section
        .push(action(
            "Add attachment…",
            Message::AddAttachment,
            app.writes_allowed() && !item.is_passkey,
        ))
        .into()
}

/// Tag and favorites filters. Tags come from the loaded item summaries, so the
/// choices always match what is in the vault.
fn tag_filters(app: &App) -> Element<'_, Message> {
    const ALL: &str = "All tags";
    let mut tags: Vec<String> = Vec::new();
    for tag in app.items.iter().flat_map(|item| &item.tags) {
        if !tags.iter().any(|t| t.eq_ignore_ascii_case(tag)) {
            tags.push(tag.clone());
        }
    }
    tags.sort_by_key(|tag| tag.to_lowercase());
    let favorites = checkbox(app.ui.favorites_only)
        .label("Favorites only")
        .on_toggle(Message::FilterFavorites);
    if tags.is_empty() && app.ui.tag.is_none() {
        return favorites.into();
    }
    let mut choices = vec![ALL.to_owned()];
    choices.extend(tags);
    let selected = app.ui.tag.clone().unwrap_or_else(|| ALL.into());
    row![
        pick_list(choices, Some(selected), |choice| Message::FilterTag(
            (choice != ALL).then_some(choice)
        ))
        .placeholder("Filter by tag")
        .width(Fill)
        .padding(8),
        favorites,
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .into()
}

/// The current page of matching items, or guidance when nothing matches.
fn item_entries(app: &App) -> Column<'_, Message> {
    let mut entries = Column::new().spacing(6);
    let matching = app.matching_items();
    let count = matching.len();
    let window = presentation::Page::items(app.ui.item_page, count);
    for offset in window.range {
        let index = if app.ui.reverse_items {
            count - 1 - offset
        } else {
            offset
        };
        let item = &app.items[matching[index]];
        // In selection mode a row shows whether it is chosen; otherwise, which is open.
        let picked = app.ui.selecting && app.ui.selected.contains(&item.id);
        let selected = picked
            || !app.ui.selecting
                && app
                    .item
                    .as_ref()
                    .is_some_and(|selected| selected.id == item.id);
        let username = item
            .username
            .as_deref()
            .filter(|username| !username.is_empty());
        let kind = model::profile(item.kind).title;
        let mut subtitle = username.map_or_else(
            || kind.to_owned(),
            |username| format!("{username} · {kind}"),
        );
        if !item.tags.is_empty() {
            subtitle = format!("{subtitle} · {}", item.tags.join(", "));
        }
        let title = match (app.ui.selecting, picked, item.favorite) {
            (true, true, _) => format!("✓ {}", item.name),
            (_, _, true) => format!("★ {}", item.name),
            _ => item.name.clone(),
        };
        // Screen readers get the whole row; the visible text fits the list's width.
        let spoken = format!("{title}, {subtitle}");
        let list_width = if app.compact() {
            app.ui.width
        } else {
            (app.ui.width * 0.32).clamp(310.0, 460.0)
        };
        // Room beside the avatar and padding, at about 0.55 em per character.
        let room = (list_width - 100.0).max(120.0);
        let (title, subtitle) = (
            clip(&title, (room / 8.8) as usize),
            clip(&subtitle, (room / 7.2) as usize),
        );
        let entry_content = row![
            avatar(&item.name, selected),
            column![text(title).size(16), text(subtitle).size(13)].spacing(3)
        ]
        .spacing(12)
        .align_y(Alignment::Center);
        entries = entries.push(
            button(entry_content)
                .selected(selected)
                .accessible_name(spoken)
                .width(Fill)
                .padding([10, 12])
                .style(move |theme: &Theme, status| {
                    let mut style = quiet_button(theme, status);
                    if selected {
                        let palette = theme.extended_palette();
                        style.background = Some(palette.primary.weak.color.into());
                        style.text_color = palette.primary.weak.text;
                        style.border.color = palette.primary.base.color;
                        style.border.width = 2.0;
                    }
                    style
                })
                .on_press_maybe((!app.busy()).then_some(if app.ui.selecting {
                    Message::SelectItem(item.id)
                } else {
                    Message::Navigate(Navigate::Select(item.id))
                })),
        );
    }
    if count == 0 {
        if app.items.is_empty() {
            entries = entries.push(text("Your first item starts here.").size(15));
        } else {
            let mut active = Vec::new();
            if !app.query.trim().is_empty() {
                active.push(format!("search “{}”", app.query.trim()));
            }
            if let Some(kind) = app.ui.kind {
                active.push(format!("type {}", model::profile(kind).title));
            }
            if let Some(tag) = &app.ui.tag {
                active.push(format!("tag {tag}"));
            }
            if app.ui.favorites_only {
                active.push("favorites only".into());
            }
            entries = entries
                .push(text("No items match.").size(15))
                .push(text(format!("Active filters: {}.", active.join(", "))).size(13))
                .push(action(
                    "Clear all filters",
                    Message::ClearFilters,
                    !app.busy(),
                ))
                .push(text("This list searches names, usernames, websites, and tags.").size(13))
                .push(action(
                    "Search notes and custom fields too",
                    Message::SearchEverything,
                    !app.busy(),
                ));
        }
    }
    entries
}

/// The secret's name mid-sentence: "password", "card number", "API key or token".
fn secret_phrase(kind: ItemKind) -> String {
    let name = model::secret_label(kind);
    let mut chars = name.chars();
    match (chars.next(), chars.next()) {
        (Some(first), Some(second)) if !second.is_uppercase() => {
            first.to_lowercase().collect::<String>() + &name[first.len_utf8()..]
        }
        _ => name,
    }
}

/// At most `limit` characters, ending in "…" when shortened.
fn clip(value: &str, limit: usize) -> String {
    if value.chars().count() <= limit {
        value.to_owned()
    } else {
        value.chars().take(limit - 1).collect::<String>() + "…"
    }
}

/// "Copy password", "Copy card number", "Copy API key or token".
fn copy_label(kind: ItemKind) -> String {
    format!("Copy {}", secret_phrase(kind))
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
                    action("Cancel", Message::CancelDelete, !app.busy()).id("cancel-delete"),
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
                            "None saved"
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
                        !app.busy() && item.has_secret
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
    if !item.tags.is_empty() {
        content = content
            .push(label("Tags"))
            .push(text(item.tags.join(", ")).size(14));
    }
    content = content.push(attachments_section(app, item));
    if !item.urls.is_empty() {
        content = content.push(label("URLs"));
        for (index, url) in item.urls.iter().enumerate() {
            content = content.push(
                row![
                    text(url).size(14).width(Fill),
                    action(
                        "Open website",
                        Message::OpenWebsite(index),
                        !app.busy() && website::address(url).is_ok()
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
        content = content.push(label("Notes")).push(if app.ui.notes_visible {
            column![
                text(notes.expose()).size(14),
                action("Hide notes", Message::ToggleNotes, true)
            ]
            .spacing(6)
        } else {
            column![action("Show notes", Message::ToggleNotes, true)]
        });
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
            // Each control names its field for screen readers ("Copy Recovery code").
            if field.secret {
                let shown = field.value.is_some();
                controls = controls.push(
                    action(
                        if shown {
                            "Hide field"
                        } else {
                            "Reveal field for 15 seconds"
                        },
                        if shown {
                            Message::HideField(target)
                        } else {
                            Message::RevealField(target)
                        },
                        !app.busy(),
                    )
                    .accessible_name(if shown {
                        format!("Hide {}", field.name)
                    } else {
                        format!("Reveal {} for 15 seconds", field.name)
                    }),
                );
            }
            controls = controls.push(
                action(
                    "Copy field",
                    Message::CopyField(target),
                    app.copying_allowed(),
                )
                .accessible_name(format!("Copy {}", field.name)),
            );
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
                !app.busy()
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
                crate::gui::styles::tip(
                    primary(
                        copy_label(item.kind),
                        Message::Copy,
                        app.copying_allowed() && item.has_secret
                    ),
                    format!("{}+Shift+P", crate::gui::styles::command_key())
                ),
                crate::gui::styles::icon_button(
                    if item.favorite {
                        crate::gui::icon_chars::STAR
                    } else {
                        crate::gui::icon_chars::STAR_BORDER
                    },
                    if item.favorite {
                        "Remove favorite"
                    } else {
                        "Add to favorites"
                    },
                    Message::ToggleFavorite,
                    app.writes_allowed() && !item.is_passkey
                ),
                crate::gui::styles::tip(
                    action("Edit item", Message::Edit, app.writes_allowed()),
                    format!("{}+E", crate::gui::styles::command_key())
                )
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
    let enabled = !app.busy();
    let validation = draft.validation();
    let profile = model::profile(draft.kind);
    let mut name = column![
        label("Name (required)"),
        text_input(profile.name_hint, &draft.name)
            .accessibility_label("Item name")
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
        .placeholder("Item type")
        .padding(8)
        .width(Fill)
    ]
    .spacing(4)
    .width(if app.compact() {
        Length::Fill
    } else {
        Length::Fixed(168.0)
    });
    let owner = column![
        label(profile.owner),
        text_input(profile.owner, &draft.username)
            .padding(10)
            .on_input_maybe(enabled.then_some(Message::Username))
    ]
    .spacing(4)
    .width(Fill);
    let secret = editor_secret(app, draft, &profile, enabled);
    let credentials: Element<'_, Message> =
        if !app.compact() && app.ui.width >= 1120.0 && !draft.multiline {
            row![owner, secret].spacing(14).into()
        } else {
            column![owner, secret].spacing(8).into()
        };
    let identity: Element<'_, Message> = if app.compact() {
        column![name, kind].spacing(10).into()
    } else {
        row![name, kind].spacing(12).into()
    };
    let mut form = column![identity, credentials].spacing(8);
    if app.editor.conflicted() {
        let mut conflict = column![
            text("This item changed in another client").size(19),
            text(
                "Your unsaved edits are kept and masked. Review the latest version, then reapply \
                 only your changes. Nothing is saved automatically."
            )
            .size(14),
            action("Review latest version", Message::ReviewConflict, enabled)
        ]
        .spacing(8);
        if let Some(latest) = app.editor.latest() {
            conflict = conflict
                .push(
                    text(format!(
                        "Latest: {} · {}\nWebsites: {}\nRevision {} · {} custom fields. Stored \
                         secrets stay hidden.",
                        latest.name,
                        latest.username.as_deref().unwrap_or("No username"),
                        latest.urls.join(", "),
                        latest.revision,
                        latest.fields.len()
                    ))
                    .size(14),
                )
                .push(
                    text(
                        "Reapplying replaces fields you edited, including edits to the same \
                         fields in the other client. Untouched fields keep their latest values.",
                    )
                    .size(14),
                )
                .push(primary(
                    "Reapply my edits to this version",
                    Message::ReapplyConflict,
                    enabled,
                ));
            if let Some(original) = &app.item {
                for comparison in draft.conflict_summary(original, latest) {
                    conflict = conflict.push(text(comparison).size(14));
                }
            }
        }
        form = form.push(panel(conflict));
    }
    form = template_fields(form, draft, &profile, enabled);
    let websites = editor_websites(draft, enabled);
    form = form
        .push(websites)
        .push(
            column![
                label("Tags (optional, comma-separated)"),
                text_input("e.g. work, finance", &draft.tags)
                    .accessibility_label("Tags, separated by commas")
                    .id("item-tags")
                    .padding(10)
                    .on_input_maybe(enabled.then_some(Message::Tags)),
                checkbox(draft.favorite)
                    .label("Favorite")
                    .on_toggle_maybe(enabled.then_some(Message::Favorite)),
            ]
            .spacing(6),
        )
        .push(
            column![
                label("Notes (optional)"),
                text_editor(&draft.notes)
                    .id("item-notes")
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
        form = editor_advanced(form, draft, &profile, &validation, enabled);
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
    let footer = editor_footer(app, draft, &validation, enabled);
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

/// Website and validation warnings above the Save and Cancel actions.
fn editor_footer<'a>(
    app: &'a App,
    draft: &'a Draft,
    validation: &model::Validation,
    enabled: bool,
) -> Column<'a, Message> {
    let mut footer = column![].spacing(8);
    for url in draft.urls.iter().filter(|url| !url.trim().is_empty()) {
        if website::address(url).is_err() {
            footer = footer.push(
                text(
                    "A website cannot be opened. Use an http:// or https:// address. Other values \
                     can still be stored.",
                )
                .size(13),
            );
            break;
        }
    }
    if draft.dirty
        && let Some(message) = validation.error
    {
        footer = footer.push(error(message));
    }
    footer = footer.push(
        row![
            primary(
                "Save item",
                Message::Save,
                app.writes_allowed() && !app.editor.conflicted() && validation.error.is_none()
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
    footer
}

/// Copy policy, multiline toggle, and custom fields.
fn editor_advanced<'a>(
    mut form: Column<'a, Message>,
    draft: &'a Draft,
    profile: &model::Profile,
    validation: &model::Validation,
    enabled: bool,
) -> Column<'a, Message> {
    form = form.push(text(profile.guidance).size(14));
    if draft.id.is_none() {
        let title = format!("Copy the {} after saving", secret_phrase(draft.kind));
        form = form
            .push(label(title.clone()))
            .push(
                pick_list(
                    model::ClipboardPolicy::ALL.as_slice(),
                    Some(draft.copy_policy),
                    Message::CopyPolicy,
                )
                .placeholder(title)
                .padding(12)
                .width(Fill),
            )
            .push(
                text("Copying is off while the clipboard timeout in Settings → Security is 0.")
                    .size(14),
            );
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
                .id(format!("custom-field-{index}"))
                .accessibility_label(format!("Custom field {} name", index + 1))
                .padding(12)
                .on_input_maybe(enabled.then_some(move |value| Message::FieldName(index, value))),
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
            .accessibility_label(format!("Custom field {} value", index + 1))
            .padding(12)
            .on_input_maybe(
                enabled.then_some(move |value: String| Message::FieldValue(index, value.into()))
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
        if let Some(message) = validation.field_error(index) {
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
    form
}

fn editor_websites(draft: &Draft, enabled: bool) -> Column<'_, Message> {
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
                    .id(format!("website-{index}"))
                    .accessibility_label(format!("Website {}", index + 1))
                    .padding(10)
                    .on_input_maybe(enabled.then_some(move |value| Message::Url(index, value))),
                action("Remove", Message::RemoveUrl(index), enabled).padding([9, 10])
            ]
            .spacing(8),
        );
    }
    websites
}

/// Suggested fields for the item type, shown as ordinary inputs.
fn template_fields<'a>(
    mut form: Column<'a, Message>,
    draft: &'a Draft,
    profile: &model::Profile,
    enabled: bool,
) -> Column<'a, Message> {
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
                .accessibility_label(name)
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
    form
}

/// The primary secret: single-line with show/generate, or multiline.
fn editor_secret<'a>(
    app: &'a App,
    draft: &'a Draft,
    profile: &model::Profile,
    enabled: bool,
) -> Column<'a, Message> {
    let mut secret = column![label(profile.secret)].spacing(4).width(Fill);
    if draft.id.is_some() {
        let phrase = secret_phrase(draft.kind);
        secret = secret.push(if draft.replace_password {
            row![
                text(format!("Enter the new {phrase} below."))
                    .size(14)
                    .width(Fill),
                action(
                    format!("Keep the saved {phrase}"),
                    Message::ReplacePassword(false),
                    enabled
                )
                .padding([9, 10]),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
        } else {
            row![
                text("•••••••• saved").width(Fill),
                action(
                    format!("Change {phrase}"),
                    Message::ReplacePassword(true),
                    enabled
                )
                .padding([9, 10]),
            ]
            .spacing(8)
            .align_y(Alignment::Center)
        });
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
            if matches!(draft.kind, ItemKind::Login | ItemKind::Wifi)
                && let Some(strength) = draft.password_strength
            {
                secret = secret.push(strength_meter(strength));
            }
        }
        if matches!(draft.kind, ItemKind::SshKey | ItemKind::SecureNote) {
            secret = secret.push(
                checkbox(draft.multiline)
                    .label("Use multiline editor (visible while editing)")
                    .on_toggle(Message::MultilineSecret),
            );
        }
    }
    secret
}

fn generator(app: &App) -> Element<'_, Message> {
    use super::generator::{Event, Policy, Toggle};
    let mut form = column![
        checkbox(app.generation.passphrase)
            .label("Generate a memorable passphrase")
            .on_toggle(Message::Passphrase),
        label(if app.generation.passphrase {
            "Number of words (3–64)"
        } else {
            "Password length (8–255)"
        }),
        text_input(
            if app.generation.passphrase { "6" } else { "20" },
            if app.generation.passphrase {
                &app.generation.words
            } else {
                &app.generation.length
            }
        )
        .accessibility_label(if app.generation.passphrase {
            "Number of words (3–64)"
        } else {
            "Password length (8–255)"
        })
        .padding(12)
        .on_input(if app.generation.passphrase {
            Message::Words
        } else {
            Message::GeneratorLength
        })
        .on_submit(Message::Generate),
    ]
    .spacing(14);
    if app.generation.passphrase {
        form = form.push(label("Word separator")).push(
            text_input("-", &app.generation.options.separator)
                .accessibility_label("Word separator")
                .padding(12)
                .on_input(|value| Message::Generator(Event::Separator(value))),
        );
    } else {
        form = form
            .push(
                row![
                    checkbox(app.generation.options.uppercase)
                        .label("A–Z")
                        .on_toggle(|value| Message::Generator(Event::Toggle(
                            Toggle::Uppercase,
                            value
                        ))),
                    checkbox(app.generation.options.lowercase)
                        .label("a–z")
                        .on_toggle(|value| Message::Generator(Event::Toggle(
                            Toggle::Lowercase,
                            value
                        ))),
                    checkbox(app.generation.options.digits)
                        .label("0–9")
                        .on_toggle(|value| Message::Generator(Event::Toggle(
                            Toggle::Digits,
                            value
                        ))),
                    checkbox(app.generation.options.symbols)
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
                checkbox(app.generation.options.ambiguous)
                    .label("Exclude look-alike characters (0, O, 1, l)")
                    .on_toggle(|value| Message::Generator(Event::Toggle(Toggle::Ambiguous, value))),
            );
    }
    if let Some(message) = app.generation.options.input_error(
        app.generation.passphrase,
        &app.generation.length,
        &app.generation.words,
    ) {
        form = form.push(error(message));
    }
    form = form.push(disclosure(
        "Generation preferences & strength checker",
        app.ui.generator_advanced,
        presentation::Disclosure::Generator,
        !app.busy(),
    ));
    if app.ui.generator_advanced {
        if !app.generation.passphrase && app.generation.options.symbols {
            form = form.push(label("Allowed symbols")).push(
                text_input(
                    "Allowed symbol characters",
                    &app.generation.options.symbol_set,
                )
                .padding(12)
                .on_input(|value| Message::Generator(Event::Symbols(value))),
            );
        }
        form = form
            .push(label("Show strength and statistics"))
            .push(
                pick_list(
                    Policy::ALL.as_slice(),
                    Some(app.generation.options.stats),
                    |value| Message::Generator(Event::Stats(value)),
                )
                .placeholder("Show strength and statistics")
                .padding(12)
                .width(Fill),
            )
            .push(label("Copy automatically after generation"))
            .push(
                pick_list(
                    Policy::ALL.as_slice(),
                    Some(app.generation.options.copy),
                    |value| Message::Generator(Event::Copy(value)),
                )
                .placeholder("Copy automatically after generation")
                .padding(12)
                .width(Fill),
            )
            .push(label(
                "Clipboard timeout override (0–255 seconds; blank uses Settings)",
            ))
            .push(
                text_input("Use saved setting", &app.generation.options.copy_timeout)
                    .accessibility_label("Clipboard timeout override in seconds")
                    .padding(12)
                    .on_input(|value| Message::Generator(Event::CopyTimeout(value))),
            )
            .push(rule::horizontal(1))
            .push(text("Check an existing password").size(20))
            .push(
                text_input(
                    "Password to assess locally",
                    app.generation.options.check.expose(),
                )
                .secure(true)
                .padding(12)
                .on_input(|value: String| Message::Generator(Event::Check(value.into())))
                .on_submit(Message::Generator(Event::Evaluate)),
            )
            .push(action(
                "Check strength",
                Message::Generator(Event::Evaluate),
                !app.busy() && !app.generation.options.check.is_empty(),
            ));
        if !app.generation.options.assessment.is_empty() {
            form = form.push(text(&app.generation.options.assessment).size(14));
        }
    }
    let policy = app.generation.options.generation_policy(&app.conf);
    if let Err(message) = &policy {
        form = form.push(error(message.clone()));
    }
    let footer = row![
        primary(
            if app.generation.value.is_empty() {
                "Generate"
            } else {
                "Generate another"
            },
            Message::Generate,
            !app.busy()
                && policy.is_ok()
                && app
                    .generation
                    .options
                    .input_error(
                        app.generation.passphrase,
                        &app.generation.length,
                        &app.generation.words
                    )
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
    if app.ui.transfer_generated && !app.generation.value.is_empty() {
        body = body.push(panel(
            column![
                text(if app.editor.is_some() {
                    "Use this password in your current draft?"
                } else {
                    "Create an item with this password?"
                })
                .size(19),
                text(
                    "This replaces the draft’s password. Other draft fields are kept. The item is \
                     saved only when you choose Save item."
                )
                .size(14),
                row![
                    primary(
                        "Use generated password",
                        Message::ConfirmGenerated,
                        app.connection.session.is_some() && !app.busy()
                    ),
                    action("Keep current draft", Message::CancelGenerated, !app.busy())
                ]
                .spacing(8)
                .wrap()
            ]
            .spacing(10),
        ));
    }
    if !app.generation.value.is_empty() {
        body = body.push(panel(
            column![
                text("Your generated password").size(18),
                text_input("Generated value", app.generation.value.expose())
                    .secure(!app.generation.value.visible())
                    .padding(12),
                app.generation
                    .value
                    .strength()
                    .map_or_else(|| column![].into(), strength_meter),
                row![
                    primary(
                        "Copy",
                        Message::CopyGenerated,
                        !app.busy()
                            && app
                                .generation
                                .options
                                .copy_timeout(&app.conf)
                                .is_ok_and(|timeout| timeout > 0)
                    ),
                    checkbox(app.generation.value.visible())
                        .label("Show value")
                        .on_toggle(Message::ShowGenerated)
                ]
                .spacing(16)
                .wrap(),
                action(
                    if app.editor.is_some() {
                        "Use in current item draft…"
                    } else {
                        "Create item with this secret…"
                    },
                    Message::UseGenerated,
                    !app.busy() && app.connection.session.is_some()
                ),
                text(if app.connection.session.is_none() {
                    "Unlock a vault to save this value directly into an item."
                } else {
                    "Transfer directly to an item without using the clipboard."
                })
                .size(14),
                text(
                    "Cleared from this screen after 60 seconds. Stored only when you save it in \
                     an item."
                )
                .size(14),
            ]
            .spacing(12),
        ));
        if !app.generation.stats.is_empty() {
            body = body.push(text(&app.generation.stats).size(14));
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
    use presentation::SettingsSection;
    let mut form = column![].spacing(14);
    form = match app.ui.settings_section {
        SettingsSection::Appearance => appearance_settings(app, form),
        SettingsSection::Vault => {
            form.push(text("Name and protect the vault that is open now.").size(14))
        }
        SettingsSection::Passwords => passwords_settings(app, form),
        SettingsSection::Security => security_settings(app, form),
        SettingsSection::Recovery => recovery_settings(app, form),
        SettingsSection::Connection => connection_settings(app, form),
        SettingsSection::Sync => form.push(cloud_settings(app)),
    };
    if app.ui.settings_section == SettingsSection::Vault {
        form = form.push(action(
            "Change master password or key file…",
            Message::OpenTools(workflows::Section::Security),
            !app.busy(),
        ));
        if app.connection.vault.is_none() {
            form = form.push(text("Unlock a vault to rename it.").size(14));
        }
    }
    if app.ui.settings_section == SettingsSection::Vault && app.connection.vault.is_some() {
        form = form
            .push(rule::horizontal(1))
            .push(text("Vault name on this device").size(19))
            .push(
                text_input("Personal or Work", &app.ui.vault_name)
                    .accessibility_label("Vault name")
                    .padding(12)
                    .on_input(Message::VaultName),
            )
            .push(action(
                "Save vault name",
                Message::RenameVault,
                app.writes_allowed() && !app.ui.vault_name.trim().is_empty(),
            ));
    }
    let footer = settings_footer(app);
    let options = column![
        SettingsSection::ALL
            .into_iter()
            .fold(row![].spacing(6), |sections, section| {
                let selected = app.ui.settings_section == section;
                sections.push(
                    button(text(section.to_string()).size(15))
                        .selected(selected)
                        .padding([8, 12])
                        .style(tab_style(selected))
                        .on_press_maybe((!app.busy()).then_some(Message::SettingsSection(section))),
                )
            })
            .wrap(),
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

/// Validation, reset confirmation, and save state for the whole settings form.
fn settings_footer(app: &App) -> Column<'_, Message> {
    let mut footer = column![].spacing(10);
    if let Err(message) = app.settings.changes() {
        footer = footer.push(error(message));
    }
    if app.confirm_reset_settings {
        footer = footer
            .push(text("Reset all settings, including appearance, to their defaults?").size(15))
            .push(
                row![
                    primary("Keep settings", Message::CancelResetSettings, !app.busy()),
                    action("Reset settings", Message::ConfirmResetSettings, !app.busy())
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
                    !app.busy() && app.settings.is_dirty() && app.settings.changes().is_ok()
                ),
                action("Reset to defaults…", Message::ResetSettings, !app.busy()),
                action("Reload saved", Message::ReloadSettings, !app.busy())
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
    footer
}

/// A labeled settings input with its validation message.
fn settings_field<'a>(
    app: &App,
    name: &'static str,
    value: &str,
    field: SettingsField,
) -> Column<'a, Message> {
    let mut control = column![
        label(name),
        text_input("", value)
            .accessibility_label(name)
            .padding(12)
            .on_input_maybe(
                (!app.busy()).then_some(move |value| Message::SettingChanged(field, value))
            )
    ]
    .spacing(6);
    if let Some(message) = app.settings.field_error(field, value) {
        control = control.push(error(message));
    }
    control
}

/// Theme and interface scale.
fn appearance_settings<'a>(app: &'a App, form: Column<'a, Message>) -> Column<'a, Message> {
    use password_manager::config::Appearance;
    form.push(
        column![
            label("Color theme"),
            pick_list(
                [
                    Appearance::System,
                    Appearance::Dark,
                    Appearance::Light,
                    Appearance::HighContrast
                ],
                Some(app.settings.appearance),
                Message::Appearance
            )
            .placeholder("Color theme")
            .padding(10)
            .width(Fill)
        ]
        .spacing(6),
    )
    .push(
        column![
            label("Text and control size"),
            pick_list(
                password_manager::config::DESKTOP_SCALES.map(presentation::ScaleChoice),
                Some(presentation::ScaleChoice(app.settings.scale)),
                |choice| Message::InterfaceScale(choice.0)
            )
            .placeholder("Text and control size")
            .padding(10)
            .width(Fill)
        ]
        .spacing(6),
    )
    .push(text("Changes preview immediately. Save settings to keep them.").size(14))
}

/// Generator and clipboard defaults.
fn passwords_settings<'a>(app: &'a App, form: Column<'a, Message>) -> Column<'a, Message> {
    form.push(settings_field(
        app,
        "Default password length (1–255)",
        &app.settings.length,
        SettingsField::Length,
    ))
    .push(
        checkbox(app.settings.stats)
            .label("Show generated password strength and statistics")
            .on_toggle(|value| Message::SettingToggled(SettingsToggle::GeneratorStats, value)),
    )
    .push(
        checkbox(app.settings.generator_copy)
            .label("Copy generated passwords automatically")
            .on_toggle(|value| Message::SettingToggled(SettingsToggle::GeneratorCopy, value)),
    )
    .push(
        checkbox(app.settings.password_copy)
            .label("Copy newly added login passwords automatically")
            .on_toggle(|value| Message::SettingToggled(SettingsToggle::PasswordCopy, value)),
    )
}

/// Lock timeout and default vault.
/// This device's passkey PIN for the unlocked vault: how key-file vaults (or
/// anyone who prefers it to the master password) confirm passkey requests.
fn passkey_pin_settings(app: &App) -> Column<'_, Message> {
    let mut section = column![label("Passkey PIN (this device)")].spacing(8);
    if app.connection.session.is_none() {
        return section.push(text("Unlock a vault to set its passkey PIN.").size(14));
    }
    let enabled = !app.busy();
    section = section
        .push(
            text(if app.ui.passkey_pin {
                "A passkey PIN is set. When a site asks for proof that it is you, confirm here \
                 with the PIN or your master password."
            } else {
                "When a site asks for proof that it is you, the passkey window can wait for you \
                 to confirm here. Password vaults use the master password; set a PIN of at \
                 least 6 characters to confirm a key-file vault, or to use instead of the \
                 master password. The PIN stays on this device."
            })
            .size(14),
        )
        .push(
            text_input("New passkey PIN", app.ui.pin_new.expose())
                .secure(true)
                .padding(12)
                .on_input_maybe(enabled.then_some(|value: String| Message::PinNew(value.into()))),
        )
        .push(
            text_input("Enter it again", app.ui.pin_confirm.expose())
                .accessibility_label("Confirm passkey PIN")
                .secure(true)
                .padding(12)
                .on_input_maybe(
                    enabled.then_some(|value: String| Message::PinConfirm(value.into())),
                ),
        );
    let mut buttons = row![action(
        if app.ui.passkey_pin {
            "Change PIN"
        } else {
            "Set PIN"
        },
        Message::SavePasskeyPin(true),
        enabled && !app.ui.pin_new.expose().is_empty(),
    )]
    .spacing(8);
    if app.ui.passkey_pin {
        buttons = buttons.push(
            action("Remove PIN", Message::SavePasskeyPin(false), enabled).style(quiet_danger),
        );
    }
    section.push(buttons)
}

fn security_settings<'a>(app: &'a App, form: Column<'a, Message>) -> Column<'a, Message> {
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
    form.push(settings_field(
        app,
        "Clear the clipboard after this many seconds (1–255; 0 turns copying off)",
        &app.settings.clipboard_timeout,
        SettingsField::ClipboardTimeout,
    ))
    .push(label("When I close the window while the vault is unlocked"))
    .push(
        pick_list(
            [
                password_manager::config::CloseAction::Ask,
                password_manager::config::CloseAction::Lock,
                password_manager::config::CloseAction::KeepUnlocked,
            ],
            Some(app.settings.close_action),
            Message::CloseBehavior,
        )
        .placeholder("When closing the window")
        .width(Fill)
        .padding(12),
    )
    .push(settings_field(
        app,
        "Lock after inactivity (15m, 1h, seconds; 0 disables)",
        &app.settings.unlock_timeout,
        SettingsField::UnlockTimeout,
    ))
    .push(label("Default vault"))
    .push(
        pick_list(choices, selected, |choice: vault_names::Choice| {
            Message::SettingChanged(SettingsField::DefaultVault, choice.id)
        })
        .placeholder("Default vault")
        .width(Fill)
        .padding(12),
    )
    .push(
        text(
            "The lock timeout applies on the next unlock. The vault also locks whenever your \
             computer locks or goes to sleep.",
        )
        .size(14),
    )
    .push(
        checkbox(app.settings.ssh_agent)
            .label("Serve SSH keys to ssh through a local agent")
            .on_toggle(|value| Message::SettingToggled(SettingsToggle::SshAgent, value)),
    )
    .push(
        text(format!(
            "Ed25519 SSH-key items are offered while their vault is unlocked. \
             Restart the local service after changing this, then set SSH_AUTH_SOCK={} (or run \
             `{}`).",
            password_manager::server::ssh_agent_socket().display(),
            if cfg!(windows) {
                "pm ssh-agent | Out-String | Invoke-Expression"
            } else {
                "eval \"$(pm ssh-agent)\""
            }
        ))
        .size(14),
    )
    .push(passkey_pin_settings(app))
    .push(action(
        "Vault credentials & security tools",
        Message::OpenTools(workflows::Section::Security),
        !app.busy(),
    ))
}

/// Backup and history retention.
fn recovery_settings<'a>(app: &'a App, form: Column<'a, Message>) -> Column<'a, Message> {
    form.push(settings_field(
        app,
        "Previous passwords kept per item (0 disables history)",
        &app.settings.history_limit,
        SettingsField::HistoryLimit,
    ))
    .push(settings_field(
        app,
        "Purge trash after days (0 keeps it indefinitely)",
        &app.settings.trash_retention,
        SettingsField::TrashRetention,
    ))
    .push(text("Restart the local service after changing recovery settings.").size(14))
    .push(action(
        "Open deleted items",
        Message::OpenTools(workflows::Section::Trash),
        !app.busy(),
    ))
    .push(action(
        "Create encrypted backup",
        Message::OpenFileTool(workflows::FileOperation::Backup),
        !app.busy(),
    ))
}

/// Local service, cloud sync, and connection details.
fn connection_settings<'a>(app: &'a App, mut form: Column<'a, Message>) -> Column<'a, Message> {
    form = form
        .push(text("Browser extension").size(19))
        .push(text("Fill and save logins in Chrome, Chromium, Helium, or Firefox.").size(14))
        .push(primary(
            "Set up browser integration…",
            Message::OpenTools(workflows::Section::Browser),
            !app.busy(),
        ))
        .push(rule::horizontal(1));
    form = form.push(
        text(if app.connection.running {
            "The local service is running. It keeps your vault available to the CLI and \
             browser extension when this window closes."
        } else {
            "The local service is stopped."
        })
        .size(15),
    );
    if app.connection.running && app.ui.restart_needed {
        form = form.push(
            column![
                text(
                    "Some saved settings apply after the service restarts. Restarting locks \
                     the vault.",
                )
                .size(14),
                primary(
                    "Restart service now",
                    Message::Restart,
                    !app.busy() && app.recovery.id().is_none(),
                ),
            ]
            .spacing(8),
        );
    }
    form = if app.connection.running {
        form.push(
            action(
                "Stop local service…",
                Message::ConfirmStop(true),
                !app.busy() && app.recovery.id().is_none(),
            )
            .style(button_style::danger),
        )
    } else {
        form.push(primary(
            "Start local service",
            Message::Connect,
            !app.busy(),
        ))
    };
    if app.ui.confirm_stop {
        form = form.push(panel(
            column![
                text("Stop the local service?").size(18),
                text(
                    "This locks the vault, discards any open item draft, and disconnects \
                     the browser extension and CLI until you start it again."
                )
                .size(14),
                row![
                    primary("Keep running", Message::ConfirmStop(false), !app.busy()),
                    action(
                        "Stop service",
                        Message::Stop,
                        !app.busy() && app.recovery.id().is_none()
                    )
                    .style(button_style::danger)
                ]
                .spacing(8)
                .wrap(),
            ]
            .spacing(12),
        ));
    }
    form.push(rule::horizontal(1))
        .push(settings_field(
            app,
            "Saved service port (1–65535)",
            &app.settings.server_port,
            SettingsField::ServerPort,
        ))
        .push(text("Stop the service before changing its saved port.").size(14))
        .push(connection_controls(app))
}

fn cloud_settings(app: &App) -> Element<'_, Message> {
    use password_manager::cloud::Action;
    let ready = !app.busy() && app.connection.running;
    let open = ready && app.connection.session.is_some();
    let has_server = !app.conf.sync.server_url.is_empty();
    let mut form = column![
        text("Cloud sync").size(22),
        text(
            "Keep vaults the same on your devices through a sync server you run yourself. \
             Connect to the server first, then turn sync on for a vault or download one you \
             already sync elsewhere.",
        )
        .size(14),
        text("1. Connect to your server").size(18),
        label("Server URL"),
        text_input(
            "https://server.your-tailnet.ts.net:8443",
            &app.settings.sync_server,
        )
        .accessibility_label("Sync server URL")
        .padding(12)
        .on_input_maybe(
            (!app.busy())
                .then_some(|value| Message::SettingChanged(SettingsField::SyncServer, value)),
        ),
        text("Choose Save settings to keep a new address.").size(13),
        label("Device credential"),
        text_input(
            "Paste a server-generated credential",
            app.cloud.token.expose(),
        )
        .secure(true)
        .padding(12)
        .on_input_maybe(
            (!app.busy()).then_some(|value: String| Message::CloudToken(value.into())),
        ),
        action(
            "Save device credential",
            Message::SaveCloudToken,
            !app.busy() && !app.cloud.token.is_empty(),
        ),
        checkbox(app.settings.sync_automatic)
            .label("Automatically synchronize enabled vaults")
            .on_toggle(|value| Message::SettingToggled(SettingsToggle::SyncAutomatic, value)),
        text("2. Sync the open vault").size(18),
    ]
    .spacing(12);
    if has_server {
        form = form.push(text(format!("Server: {}", app.conf.sync.server_url)).size(14));
    }
    if app.connection.session.is_none() {
        form = form.push(text("Unlock a vault to turn sync on or off for it.").size(14));
    }
    form = form
        .push(
            row![
                primary("Sync now", Message::Cloud(Action::Now), open),
                action("Turn on sync", Message::Cloud(Action::Enable), open),
                action("Turn off sync", Message::Cloud(Action::Disable), open).style(quiet_danger),
            ]
            .spacing(8)
            .wrap(),
        )
        .push(text("Details").size(14))
        .push(
            row![
                action("Check for changes", Message::Cloud(Action::Check), open),
                action("Sync status", Message::Cloud(Action::Status), open),
                action("Review conflicts", Message::Cloud(Action::Conflicts), open),
            ]
            .spacing(8)
            .wrap(),
        )
        .push(text("3. Download a vault from the server").size(18))
        .push(action(
            "Refresh cloud vaults",
            Message::Cloud(Action::List),
            ready && has_server,
        ));
    if !has_server {
        form = form.push(text("Save a server URL first.").size(14));
    }
    if !app.cloud.vaults.is_empty() {
        form = form.push(
            pick_list(
                app.cloud.vaults.as_slice(),
                app.cloud.vault.as_ref(),
                Message::CloudVault,
            )
            .placeholder("Cloud vault"),
        );
        if let Some(id) = &app.cloud.vault {
            form = form
                .push(
                    row![
                        primary(
                            "Download selected vault",
                            Message::Cloud(Action::Pull(id.clone())),
                            ready
                        ),
                        action(
                            "Download comparison copy",
                            Message::Cloud(Action::PullCopy(id.clone())),
                            ready
                        ),
                    ]
                    .spacing(8)
                    .wrap(),
                )
                .push(
                    text(
                        "A comparison copy has synchronization disabled and leaves existing local \
                         vaults intact.",
                    )
                    .size(14),
                );
        }
    }
    if let Some(review) = &app.cloud.review {
        use password_manager::cloud::Side;
        form = form.push(text("Resolve item differences").size(20)).push(
            text(
                "Choose every differing field. Protected values stay hidden. Metadata includes \
                 item type, URLs and custom fields; authenticators, history and deletion state \
                 are chosen as groups. Both complete vault versions are saved as encrypted \
                 recovery copies before applying.",
            )
            .size(14),
        );
        if !review.items.is_empty() {
            form = form.push(
                row![
                    action(
                        "Choose all local",
                        Message::CloudChooseAll(Side::Local),
                        ready
                    ),
                    action(
                        "Choose all cloud",
                        Message::CloudChooseAll(Side::Remote),
                        ready
                    ),
                ]
                .spacing(8)
                .wrap(),
            );
        }
        for item in &review.items {
            let name = item.local.split(" · ").next().unwrap_or_default();
            form = form.push(text(name.to_owned()).size(18)).push(
                row![
                    text(format!("Local: {}", item.local)).width(Length::FillPortion(1)),
                    text(format!("Cloud: {}", item.remote)).width(Length::FillPortion(1))
                ]
                .spacing(12),
            );
            for field in &item.fields {
                let selected = app
                    .cloud
                    .choices
                    .iter()
                    .find(|c| c.id == item.id && c.field == field.field)
                    .map(|c| c.side);
                let id = item.id;
                let local_field = field.field.clone();
                let remote_field = field.field.clone();
                let title = match field.field.as_str() {
                    "password" => "Password (or the item's main secret)",
                    "notes" => "Notes",
                    "metadata" => "Type, URLs and custom fields",
                    "history" => "Password history",
                    "authenticator" => "Authenticator",
                    "duo" => "Duo enrollment",
                    "lifecycle" => "Active or deleted",
                    "created" => "Created",
                    "item" => "Item presence",
                    "name" => "Name",
                    "username" => "Username",
                    "url" => "Website",
                    other => other,
                };
                form = form.push(text(title.to_owned())).push(
                    row![
                        column![
                            text(field.local.clone()),
                            action(
                                if selected == Some(Side::Local) {
                                    "✓ Keep local"
                                } else {
                                    "Keep local"
                                },
                                Message::CloudChoice(id, local_field, Side::Local),
                                ready
                            )
                        ]
                        .width(Length::FillPortion(1))
                        .spacing(6),
                        column![
                            text(field.remote.clone()),
                            action(
                                if selected == Some(Side::Remote) {
                                    "✓ Keep cloud"
                                } else {
                                    "Keep cloud"
                                },
                                Message::CloudChoice(id, remote_field, Side::Remote),
                                ready
                            )
                        ]
                        .width(Length::FillPortion(1))
                        .spacing(6),
                    ]
                    .spacing(12),
                );
            }
        }
        let complete = review.items.iter().all(|item| {
            item.fields.iter().all(|f| {
                app.cloud
                    .choices
                    .iter()
                    .any(|c| c.id == item.id && c.field == f.field)
            })
        });
        form = form.push(action(
            "Apply selected values and sync",
            Message::ResolveCloud,
            ready
                && complete
                && app.writes_allowed()
                && !app.editor.as_ref().is_some_and(|d| d.dirty),
        ));
    }
    panel(form).into()
}
