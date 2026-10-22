use super::*;
use iced::{
    Alignment, Fill, Length,
    widget::{
        Column, button, checkbox, column, container, pick_list, row, rule, scrollable, text,
        text_editor, text_input,
    },
};

fn action<'a>(
    label: &'a str,
    message: Message,
    enabled: bool,
) -> iced::widget::Button<'a, Message> {
    button(label)
        .padding([9, 14])
        .on_press_maybe(enabled.then_some(message))
}

fn label(value: &str) -> iced::widget::Text<'_> {
    text(value).size(13)
}

fn panel<'a>(content: impl Into<Element<'a, Message>>) -> iced::widget::Container<'a, Message> {
    container(content).padding(22).style(container::rounded_box)
}

pub(super) fn view(app: &App) -> Element<'_, Message> {
    let controls = row![
        action("Vault", Message::Tab(Tab::Vault), !app.busy),
        action("Generator", Message::Tab(Tab::Generator), !app.busy),
        action("Settings", Message::Tab(Tab::Settings), !app.busy),
        action(
            "Lock vault",
            Message::Lock,
            app.running && app.session.is_some()
        ),
        if app.running {
            action(
                "Stop server",
                Message::Stop,
                !app.busy && app.pending.is_none(),
            )
            .style(button::danger)
        } else {
            action("Start server", Message::Connect, !app.busy)
        },
    ]
    .spacing(10)
    .align_y(Alignment::Center)
    .wrap()
    .align_x(iced::alignment::Horizontal::Right);
    let header = row![
        text("Password Manager").size(25),
        container(controls).align_right(Fill)
    ]
    .spacing(10)
    .align_y(Alignment::Center);

    let content: Element<'_, Message> = match app.tab {
        Tab::Vault if !app.running => panel(
            column![
                text("Connect to your vault").size(24),
                action("Start / reconnect", Message::Connect, !app.busy),
            ]
            .spacing(18),
        )
        .width(Fill)
        .into(),
        Tab::Vault if app.session.is_none() => unlock(app),
        Tab::Vault => vault(app),
        Tab::Generator => generator(app),
        Tab::Settings => settings(app),
    };
    let mut page = column![header, rule::horizontal(1), content].spacing(18);
    if let Some(id) = &app.pending {
        let mut recovery = column![
            text("A previous change needs review").size(17),
            text(format!("Operation {id}")).size(12),
            action(
                "Check last change",
                Message::Reconcile,
                !app.busy && app.running
            ),
        ]
        .spacing(8);
        if app.reviewed {
            recovery = recovery.push(action(
                "I inspected the vault; allow new changes",
                Message::Acknowledge,
                !app.busy,
            ));
        }
        page = page.push(panel(recovery));
    }
    if let Some(warning) = &app.warning {
        page = page.push(text(warning).size(12));
    }
    if app.busy || !app.notice.is_empty() {
        page = page.push(text(if app.busy { "Working…" } else { &app.notice }).size(13));
    }
    container(page).padding(24).width(Fill).height(Fill).into()
}

fn unlock(app: &App) -> Element<'_, Message> {
    let enabled = !app.busy;
    let mut form = column![
        text(if app.creating {
            "Create a vault"
        } else {
            "Unlock your vault"
        })
        .size(25),
        text(if app.creating {
            "Choose a strong master password of at least 14 characters."
        } else {
            "Your vault stays encrypted until you unlock it."
        })
        .size(14),
    ]
    .spacing(14);
    if !app.creating {
        form = form.push(label("Vault"));
        if app.vaults.is_empty() {
            form = form.push(text("No vaults yet. Create your first vault below."));
        } else {
            form = form.push(
                pick_list(app.vaults.as_slice(), app.vault.as_ref(), Message::Vault)
                    .width(Fill)
                    .padding(10),
            );
        }
    }
    form = form.push(label("Master password")).push(
        text_input("Enter master password", app.master.expose())
            .secure(true)
            .padding(12)
            .on_input_maybe(enabled.then_some(|value: String| Message::Master(value.into())))
            .on_submit_maybe(
                (enabled
                    && (!app.creating || app.pending.is_none())
                    && (app.creating || !app.vaults.is_empty()))
                .then_some(if app.creating {
                    Message::Create
                } else {
                    Message::Unlock
                }),
            ),
    );
    if app.creating {
        form = form
            .push(label("Confirm master password"))
            .push(
                text_input("Enter it again", app.confirmation.expose())
                    .secure(true)
                    .padding(12)
                    .on_input_maybe(
                        enabled.then_some(|value: String| Message::ConfirmMaster(value.into())),
                    )
                    .on_submit_maybe(app.writes_allowed().then_some(Message::Create)),
            )
            .push(action(
                "Create vault",
                Message::Create,
                app.writes_allowed(),
            ))
            .push(action("Back to unlock", Message::Creating(false), enabled));
    } else {
        form = form
            .push(label("Or an external key file"))
            .push(
                row![
                    text_input("Absolute path to your key file", app.key_path.expose())
                        .padding(10)
                        .on_input_maybe(
                            enabled.then_some(|value: String| Message::KeyPath(value.into())),
                        ),
                    action("Browse…", Message::BrowseKey, enabled),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            )
            .push(action(
                "Unlock vault",
                Message::Unlock,
                enabled && !app.vaults.is_empty(),
            ))
            .push(rule::horizontal(1))
            .push(action(
                "Create a new vault",
                Message::Creating(true),
                app.writes_allowed(),
            ));
    }
    container(panel(scrollable(form).spacing(8)).max_width(540))
        .center_x(Fill)
        .center_y(Fill)
        .height(Fill)
        .into()
}

fn vault(app: &App) -> Element<'_, Message> {
    let query = app.query.to_lowercase();
    let mut entries = Column::new().spacing(7);
    let mut count = 0;
    for item in &app.items {
        if !query.is_empty()
            && !std::iter::once(item.name.as_str())
                .chain(item.username.as_deref())
                .chain(item.urls.iter().map(String::as_str))
                .any(|value| value.to_lowercase().contains(&query))
        {
            continue;
        }
        count += 1;
        let selected = app
            .item
            .as_ref()
            .is_some_and(|selected| selected.id == item.id);
        let mut entry_content = column![text(&item.name).size(16)].spacing(4);
        if let Some(username) = item
            .username
            .as_deref()
            .filter(|username| !username.is_empty())
        {
            entry_content = entry_content.push(text(username).size(12));
        }
        let entry = button(entry_content)
            .width(Fill)
            .padding(13)
            .style(if selected {
                button::primary
            } else {
                button::secondary
            })
            .on_press_maybe((!app.busy).then_some(Message::Navigate(Navigate::Select(item.id))));
        entries = entries.push(entry);
    }
    if count == 0 {
        entries = entries.push(
            text(if app.items.is_empty() {
                "Your vault is empty. Add your first item."
            } else {
                "No matching items."
            })
            .size(14),
        );
    }
    let sidebar = column![
        text_input("Search items", &app.query)
            .padding(11)
            .on_input(Message::Search),
        row![
            action(
                "Add item",
                Message::Navigate(Navigate::New),
                app.writes_allowed()
            ),
            action("Refresh", Message::Navigate(Navigate::Refresh), !app.busy)
        ]
        .spacing(8),
        text(format!("{count} items")).size(13),
        scrollable(entries).spacing(8).height(Fill),
    ]
    .spacing(12)
    .width(Length::FillPortion(2));
    let detail = if let Some(draft) = &app.draft {
        editor(app, draft)
    } else if let Some(item) = &app.item {
        details(app, item)
    } else {
        panel(
            column![
                text("Your vault").size(25),
                text("Select an item to view it, or add a new one.").size(15)
            ]
            .spacing(16),
        )
        .width(Fill)
        .height(Fill)
        .into()
    };
    let mut body = column![
        row![
            sidebar,
            container(detail).width(Length::FillPortion(3)).height(Fill)
        ]
        .spacing(20)
        .height(Fill)
    ]
    .spacing(12)
    .height(Fill);
    if app.deferred.is_some() {
        body = body.push(panel(
            row![
                text("Discard unsaved changes?").width(Fill),
                action("Keep editing", Message::KeepEditing, !app.busy),
                action("Discard changes", Message::Discard, !app.busy).style(button::danger),
            ]
            .spacing(10)
            .align_y(Alignment::Center),
        ));
    }
    body.into()
}

fn details<'a>(app: &'a App, item: &'a ItemDetail) -> Element<'a, Message> {
    let mut content = column![
        text(&item.name).size(25),
        row![
            action("Edit item", Message::Edit, app.writes_allowed()),
            action("Move to trash", Message::Delete, app.writes_allowed()).style(button::danger)
        ]
        .spacing(10),
        rule::horizontal(1),
        label("Username / owner"),
        text(item.username.as_deref().unwrap_or("—")),
        label("Primary secret"),
        text(
            item.password
                .as_ref()
                .map(SecretString::expose)
                .unwrap_or(if item.has_secret {
                    "••••••••••••"
                } else {
                    "No primary secret"
                })
        ),
        row![
            action(
                "Copy secret",
                Message::Copy,
                app.writes_allowed() && item.has_secret
            ),
            action(
                if app.reveal_until.is_some() {
                    "Hide secrets"
                } else {
                    "Reveal for 15 seconds"
                },
                Message::Reveal,
                !app.busy
            )
        ]
        .spacing(10),
    ]
    .spacing(13);
    if !item.urls.is_empty() {
        content = content.push(label("URLs"));
        for url in &item.urls {
            content = content.push(text(url).size(14));
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
        for field in &item.fields {
            content = content.push(
                column![
                    text(&field.name).size(13),
                    text(
                        field
                            .value
                            .as_ref()
                            .map(SecretString::expose)
                            .unwrap_or("••••••••")
                    )
                    .size(14)
                ]
                .spacing(4),
            );
        }
    }
    if item.has_totp || item.has_duo {
        content = content.push(text("An authenticator is attached. Manage codes and Duo through the CLI or browser extension.").size(12));
    }
    content = content.push(
        text(format!(
            "Created {}\nModified {}",
            item.created, item.modified
        ))
        .size(11),
    );
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
                    .style(button::danger)
                ]
                .spacing(10),
            );
    }
    panel(scrollable(content).spacing(8))
        .height(Fill)
        .width(Fill)
        .into()
}

fn editor<'a>(app: &'a App, draft: &'a Draft) -> Element<'a, Message> {
    let enabled = !app.busy;
    let mut form = column![
        text(if draft.id.is_some() {
            "Edit item"
        } else {
            "New item"
        })
        .size(24),
        label("Name"),
        text_input("Item name", &draft.name)
            .padding(10)
            .on_input_maybe(enabled.then_some(Message::Name)),
        label("Type"),
        pick_list(model::KINDS.as_slice(), Some(draft.kind), Message::Kind)
            .padding(10)
            .width(Fill),
        label("Username / owner"),
        text_input("Username", &draft.username)
            .padding(10)
            .on_input_maybe(enabled.then_some(Message::Username)),
    ]
    .spacing(10);
    if draft.id.is_some() {
        form = form.push(
            checkbox(draft.replace_password)
                .label("Replace the existing primary secret")
                .on_toggle(Message::ReplacePassword),
        );
    }
    if draft.id.is_none() || draft.replace_password {
        form = form.push(
            text_input("Primary secret", draft.password.expose())
                .secure(true)
                .padding(10)
                .on_input_maybe(enabled.then_some(|value: String| Message::Password(value.into()))),
        );
    }
    form = form
        .push(action(
            "Generate replacement password",
            Message::Generate,
            enabled,
        ))
        .push(label("URLs"));
    for (index, url) in draft.urls.iter().enumerate() {
        form = form.push(
            row![
                text_input("https://example.com", url)
                    .padding(10)
                    .on_input_maybe(enabled.then_some(move |value| Message::Url(index, value))),
                action("Remove", Message::RemoveUrl(index), enabled)
            ]
            .spacing(8),
        );
    }
    form = form.push(action("Add URL", Message::AddUrl, enabled))
        .push(label("Notes"))
        .push(text_editor(&draft.notes).placeholder("Private notes").height(140).padding(10).on_action(Message::Notes))
        .push(text("Existing custom fields and authenticators are preserved. Use the CLI to manage them.").size(12))
        .push(row![action("Save item", Message::Save, app.writes_allowed()), action("Cancel", Message::Navigate(Navigate::Close), enabled)].spacing(10));
    panel(scrollable(form).spacing(8))
        .height(Fill)
        .width(Fill)
        .into()
}

fn generator(app: &App) -> Element<'_, Message> {
    let mut form = column![
        text("Password generator").size(25),
        text("Generate locally. Nothing is saved until you use it in an item.").size(14),
        checkbox(app.passphrase)
            .label("Generate a passphrase")
            .on_toggle(Message::Passphrase),
    ]
    .spacing(16);
    form = if app.passphrase {
        form.push(label("Number of words (1–32)")).push(
            text_input("6", &app.words)
                .padding(10)
                .on_input(Message::Words),
        )
    } else {
        form.push(label("Password length (1–255)")).push(
            text_input("20", &app.generator_length)
                .padding(10)
                .on_input(Message::GeneratorLength),
        )
    };
    form = form.push(action("Generate", Message::Generate, !app.busy));
    if !app.generated.is_empty() {
        form = form.push(text_input("Generated value", app.generated.expose()).secure(!app.show_generated).padding(12))
            .push(checkbox(app.show_generated).label("Show generated value").on_toggle(Message::ShowGenerated))
            .push(action("Copy generated value", Message::CopyGenerated, !app.busy && app.conf.clipboard.timeout > 0))
            .push(text("Cleared from this screen after 60 seconds. Clipboard cleanup uses your configured timeout.").size(12));
        if !app.generated_stats.is_empty() {
            form = form.push(text(&app.generated_stats).size(13));
        }
    }
    container(panel(scrollable(form).spacing(8)).max_width(600))
        .center_x(Fill)
        .height(Fill)
        .into()
}

fn settings(app: &App) -> Element<'_, Message> {
    let field = |name: &'static str, value: &str, field: SettingsField| {
        column![
            label(name),
            text_input("", value)
                .padding(10)
                .on_input(move |value| Message::SettingChanged(field, value)),
        ]
        .spacing(6)
    };
    let mut choices = vec![String::from("Automatic selection")];
    choices.extend(app.vaults.iter().cloned());
    if !app.settings.default_vault.is_empty() && !choices.contains(&app.settings.default_vault) {
        choices.push(app.settings.default_vault.clone());
    }
    let selected = if app.settings.default_vault.is_empty() {
        "Automatic selection".to_owned()
    } else {
        app.settings.default_vault.clone()
    };
    let mut form = column![
        text("Settings").size(25),
        text("Passwords").size(18),
        field(
            "Default password length (1–255)",
            &app.settings.length,
            SettingsField::Length
        ),
        checkbox(app.settings.stats)
            .label("Show generated password strength and statistics")
            .on_toggle(|value| Message::SettingToggled(SettingsToggle::GeneratorStats, value)),
        checkbox(app.settings.generator_copy)
            .label("Copy generated passwords automatically")
            .on_toggle(|value| Message::SettingToggled(SettingsToggle::GeneratorCopy, value)),
        checkbox(app.settings.password_copy)
            .label("Copy newly added login passwords automatically")
            .on_toggle(|value| Message::SettingToggled(SettingsToggle::PasswordCopy, value)),
        rule::horizontal(1),
        text("Security").size(18),
        field(
            "Clear clipboard after seconds (0 disables copying)",
            &app.settings.clipboard_timeout,
            SettingsField::ClipboardTimeout
        ),
        field(
            "Lock after inactivity (seconds, 15m, 1h, or 1d; 0 disables)",
            &app.settings.unlock_timeout,
            SettingsField::UnlockTimeout
        ),
        label("Default vault"),
        pick_list(choices, Some(selected), |value: String| {
            Message::SettingChanged(
                SettingsField::DefaultVault,
                if value == "Automatic selection" {
                    String::new()
                } else {
                    value
                },
            )
        })
        .width(Fill)
        .padding(10),
        text("The lock timeout applies on the next unlock.").size(12),
        rule::horizontal(1),
        text("Recovery").size(18),
        field(
            "Previous passwords kept per item (0 disables history)",
            &app.settings.history_limit,
            SettingsField::HistoryLimit
        ),
        field(
            "Purge trash after days (0 keeps it indefinitely)",
            &app.settings.trash_retention,
            SettingsField::TrashRetention
        ),
        text("Restart the server after changing recovery settings.").size(12),
        rule::horizontal(1),
        text("Server").size(18),
        field(
            "Server port (1–65535)",
            &app.settings.server_port,
            SettingsField::ServerPort
        ),
        text("Stop the server before changing its port.").size(12),
        rule::horizontal(1),
        row![
            action("Save settings", Message::SaveSettings, !app.busy),
            action("Reset to defaults", Message::ResetSettings, !app.busy).style(button::secondary),
        ]
        .spacing(10),
    ]
    .spacing(14);
    if app.confirm_reset_settings {
        form = form.push(panel(
            column![
                text("Reset all settings to their defaults?"),
                row![
                    action("Cancel", Message::CancelResetSettings, !app.busy),
                    action("Reset settings", Message::ConfirmResetSettings, !app.busy)
                        .style(button::danger)
                ]
                .spacing(10),
            ]
            .spacing(10),
        ));
    }
    container(panel(scrollable(form).spacing(8)).max_width(650))
        .center_x(Fill)
        .height(Fill)
        .into()
}
