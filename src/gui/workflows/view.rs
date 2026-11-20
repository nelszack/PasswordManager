use super::*;
use crate::gui::Message as AppMessage;
use crate::gui::styles::{self, quiet_button, quiet_danger};
use crate::gui::widgets::{button, checkbox, pick_list, scrollable, text_input};
use iced::widget::button as button_style;
use iced::{
    Fill,
    widget::{Column, column, container, row, rule, text},
};

fn event(value: Event) -> AppMessage {
    AppMessage::Workflow(value)
}
/// Workflow actions share the main view's button styling; data-moving and
/// review actions are primary.
fn action<'a>(label: &'a str, value: Action, enabled: bool) -> crate::gui::widgets::Button<'a> {
    let primary = matches!(
        value,
        Action::Trash
            | Action::History
            | Action::RestoreTrash(_)
            | Action::Audit
            | Action::Search
            | Action::Backup
            | Action::PreviewImport
            | Action::Export
            | Action::NewVault
            | Action::RestoreBackup
            | Action::Import
    );
    let message = event(Event::Run(value));
    if primary {
        styles::primary(label, message, enabled)
    } else {
        styles::action(label, message, enabled)
    }
}
fn field<'a>(
    label: &'a str,
    value: &'a str,
    key: Field,
    secret: bool,
    enabled: bool,
) -> Element<'a, AppMessage> {
    column![
        styles::label(label),
        text_input(label, value)
            .secure(secret)
            .padding(10)
            .on_input_maybe(
                enabled.then_some(move |value: String| event(Event::Field(key, value.into())))
            )
    ]
    .spacing(6)
    .into()
}
fn toggle<'a>(label: &'a str, value: bool, key: Toggle, enabled: bool) -> Element<'a, AppMessage> {
    checkbox(value)
        .label(label)
        .on_toggle_maybe(enabled.then_some(move |value| event(Event::Toggle(key, value))))
        .into()
}
fn path<'a>(
    label: &'a str,
    value: &'a str,
    key: Field,
    save: bool,
    enabled: bool,
) -> Element<'a, AppMessage> {
    column![
        styles::label(label),
        row![
            text_input("Choose or enter a file path", value)
                .padding(10)
                .on_input_maybe(
                    enabled.then_some(move |value: String| event(Event::Field(key, value.into())))
                ),
            styles::action("Browse…", event(Event::Pick(key, save)), enabled)
        ]
        .spacing(8)
    ]
    .spacing(6)
    .into()
}
fn credentials<'a>(state: &'a State, new: bool, enabled: bool) -> Column<'a, AppMessage> {
    let mut form = column![toggle(
        "Use an external key file",
        state.credentials.use_key,
        Toggle::UseKey,
        enabled
    )]
    .spacing(12);
    if state.credentials.use_key {
        form = form.push(path(
            if new {
                "New key file (must not already exist)"
            } else {
                "Existing key file"
            },
            &state.credentials.key_path,
            Field::KeyPath,
            new,
            enabled,
        ));
    } else {
        form = form.push(field(
            "Password",
            state.credentials.password.expose(),
            Field::Password,
            true,
            enabled,
        ));
        if new {
            form = form.push(field(
                "Confirm password",
                state.credentials.confirmation.expose(),
                Field::Confirmation,
                true,
                enabled,
            ));
        }
    }
    form
}

pub(super) fn confirmation<'a>(state: &'a State, app: &'a App) -> Column<'a, AppMessage> {
    let enabled = !app.busy();
    let mut form = column![].spacing(12);
    if let Some(prepared) = &state.prepared {
        form = form
            .push(rule::horizontal(1))
            .push(
                text(
                    prepared
                        .confirmation
                        .as_deref()
                        .unwrap_or("Confirm this operation?"),
                )
                .size(16),
            )
            .push(
                row![
                    styles::primary("Cancel", event(Event::Cancel), enabled),
                    styles::action(
                        prepared.action.confirm_label(),
                        event(Event::Confirm),
                        enabled && app.recovery.id().is_none()
                    )
                    .style(if prepared.action.dangerous(state.files.force) {
                        button_style::danger
                    } else {
                        button_style::primary
                    }),
                ]
                .spacing(10)
                .wrap(),
            );
    }
    form
}

fn duo_options<'a>(state: &'a State, app: &'a App) -> Column<'a, AppMessage> {
    let mut form = column![].spacing(12);
    if !state.duo.watch.as_ref().is_some_and(|target| {
        state
            .selected
            .as_ref()
            .is_some_and(|choice| choice.id == target.choice.id)
    }) {
        return form;
    }
    form = form
        .push(field(
            "Duo refresh interval (3–60 seconds)",
            &state.authenticator.duo_interval,
            Field::DuoInterval,
            false,
            !app.busy(),
        ))
        .push(toggle(
            "Show private desktop alerts for new Duo requests",
            state.duo.notify,
            Toggle::NotifyDuo,
            !app.busy(),
        ));
    if let Err(error) = state.authenticator.duo_interval_seconds() {
        form = form.push(text(error).size(14));
    }
    if let Some(target) = state.duo.watch.as_ref() {
        form = form.push(
            text(format!(
                "Watching {}. Review each request here before responding.",
                target.choice
            ))
            .size(14),
        );
    }
    form
}

fn duo_requests<'a>(state: &'a State, app: &'a App) -> Column<'a, AppMessage> {
    let enrolled = state
        .selected
        .as_ref()
        .is_some_and(|choice| app.has_duo(choice.id));
    let unlocked =
        !app.busy() && app.connection.running && app.connection.session.is_some() && enrolled;
    let writes = unlocked && app.recovery.id().is_none() && state.prepared.is_none();
    let mut form = column![
        text("Duo Push requests").size(19),
        row![
            action("Fetch Push requests", Action::Requests, unlocked),
            toggle(
                "Watch Duo requests in background",
                state.duo.watch.as_ref().is_some_and(|target| state
                    .selected
                    .as_ref()
                    .is_some_and(|choice| choice.id == target.choice.id)),
                Toggle::WatchDuo,
                unlocked
            ),
        ]
        .spacing(12)
        .wrap(),
    ]
    .spacing(12);
    if !enrolled {
        return form
            .push(
                text(
                    "Select a Push-enrolled item to receive requests. Passcodes-only enrollment \
                     does not support Push.",
                )
                .size(14),
            )
            .push(duo_options(state, app));
    }
    if app.tab != Tab::Vault
        && state
            .prepared
            .as_ref()
            .is_some_and(|prepared| matches!(prepared.action, Action::Respond(..)))
    {
        form = form.push(confirmation(state, app));
    }
    let Some(requests) = state.duo_requests_for(app) else {
        return form
            .push(text(if app.polling() || app.busy() {
                "Fetching Push requests…"
            } else {
                "Fetch requests to check for a pending login."
            }))
            .push(duo_options(state, app));
    };
    if requests.is_empty() {
        form = form.push(text("No pending Push requests."));
    } else if state.duo_review_pending(app) {
        form = form
            .push(text("Refresh paused while you review. Fetch requests to check again.").size(14));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    for (index, request) in requests.iter().enumerate() {
        let current = request.expires_at > now;
        let mut card = column![
            text(&request.application).size(18),
            text(format!(
                "Account: {}\nLocation: {}\n{}\nExpires {}",
                request.username,
                request.location,
                request.summary,
                expiry(request.expires_at)
            )),
            text(request.unsupported.as_deref().unwrap_or(if current {
                "Review this request before responding."
            } else {
                "This request has expired."
            }))
            .size(14),
        ]
        .spacing(8);
        if let Some(digits) = request.code_digits {
            card = card
                .push(field(
                    "Verified Push code from the login page",
                    state.authenticator.code.expose(),
                    Field::Code,
                    true,
                    unlocked,
                ))
                .push(
                    text(format!(
                        "Enter the {digits}-digit code shown for this request."
                    ))
                    .size(14),
                );
        }
        form = form
            .push(
                card.push(
                    row![
                        action(
                            "Approve",
                            Action::Respond(index, true),
                            writes && current && request.unsupported.is_none()
                        ),
                        action("Deny", Action::Respond(index, false), writes && current)
                            .style(button_style::danger),
                    ]
                    .spacing(10),
                ),
            )
            .push(rule::horizontal(1));
    }
    form.push(duo_options(state, app))
}

pub(super) fn account_authenticators<'a>(
    state: &'a State,
    app: &'a App,
    item: &'a password_manager::vault::ItemDetail,
) -> Column<'a, AppMessage> {
    let mut form = column![].spacing(12);
    if !state
        .selected
        .as_ref()
        .is_some_and(|choice| choice.id == item.id)
    {
        return form;
    }
    if item.has_duo {
        form = form
            .push(duo_requests(state, app))
            .push(rule::horizontal(1));
    }
    if item.has_totp {
        let writes =
            app.writes_allowed() && app.connection.session.is_some() && state.prepared.is_none();
        let copy_enabled = state.authenticator.otp_copy_timeout.trim().is_empty()
            || state
                .authenticator
                .otp_timeout(app.conf.clipboard.timeout)
                .is_ok_and(|timeout| timeout.is_some());
        let code = state.otp_result_for(app);
        form = form.push(text("One-time password").size(19)).push(
            row![
                action("Show code", Action::ShowOtp(false), writes),
                action("Copy code", Action::ShowOtp(true), writes && copy_enabled),
                styles::primary("Hide code", AppMessage::HideSecrets, code.is_some()),
            ]
            .spacing(8)
            .wrap(),
        );
        if let Some(code) = code {
            form = form.push(text(code.code.expose()).size(26)).push(
                text(
                    code.counter
                        .map(|counter| {
                            format!("HOTP counter {counter}; its next counter has been saved.")
                        })
                        .unwrap_or_else(|| {
                            format!(
                                "TOTP: {} seconds remaining when fetched.",
                                code.expires_in.unwrap_or_default()
                            )
                        }),
                )
                .size(14),
            );
        }
        form = form.push(toggle(
            "OTP options",
            state.otp.options_open,
            Toggle::OtpOptions,
            !app.busy(),
        ));
        if state.otp.options_open {
            form = form
                .push(field(
                    "OTP copy timeout in seconds (0–255; blank uses clipboard setting)",
                    &state.authenticator.otp_copy_timeout,
                    Field::OtpCopyTimeout,
                    false,
                    !app.busy(),
                ))
                .push(
                    text(
                        state
                            .authenticator
                            .otp_timeout(app.conf.clipboard.timeout)
                            .err()
                            .unwrap_or_else(|| "Zero disables OTP copying.".into()),
                    )
                    .size(14),
                )
                .push(toggle(
                    "Copy each new time-based code once while watching",
                    state.otp.copy,
                    Toggle::CopyWatchedOtp,
                    writes && copy_enabled,
                ))
                .push(toggle(
                    "Watch time-based codes",
                    state.otp.watch.is_some(),
                    Toggle::WatchOtp,
                    writes,
                ));
        }
        form = form.push(
            text(
                "Showing or copying HOTP consumes its next counter. Codes hide after 15 seconds \
                 or on focus loss. Watching supports TOTP only.",
            )
            .size(14),
        );
    }
    form
}

pub(super) fn authenticator_editor<'a>(state: &'a State, app: &'a App) -> Column<'a, AppMessage> {
    let mut form = column![text("Authenticator & Duo").size(20)].spacing(12);
    let Some(draft) = app.editor.as_ref() else {
        return form;
    };
    let Some(item) = app.item.as_ref().filter(|item| Some(item.id) == draft.id) else {
        return form.push(text(
            "Save the new item, then edit it to add an authenticator or Duo.",
        ));
    };
    let enabled = app.writes_allowed() && !draft.dirty;
    let writes = enabled && state.prepared.is_none();
    if draft.dirty {
        return form
            .push(
                text("Save your item changes before changing its authenticator or Duo enrollment.")
                    .size(14),
            )
            .push(styles::primary(
                "Save changes & continue editing",
                AppMessage::SaveAndEdit,
                app.writes_allowed(),
            ));
    }
    form = form
        .push(
            text(if item.has_totp {
                "Authenticator configured"
            } else {
                "No authenticator configured"
            })
            .size(14),
        )
        .push(field(
            "Base32 secret or otpauth URI",
            state.authenticator.configuration.expose(),
            Field::Configuration,
            true,
            enabled,
        ))
        .push(
            row![
                action(
                    if item.has_totp {
                        "Replace authenticator"
                    } else {
                        "Add authenticator"
                    },
                    Action::SetOtp,
                    writes
                ),
                action(
                    "Remove authenticator",
                    Action::RemoveOtp,
                    writes && item.has_totp
                )
                .style(button_style::danger),
            ]
            .spacing(8)
            .wrap(),
        )
        .push(rule::horizontal(1))
        .push(
            text(if item.has_duo {
                "Duo Push configured"
            } else {
                "No Duo Push enrollment"
            })
            .size(14),
        )
        .push(field(
            "Fresh Duo activation link",
            state.authenticator.activation.expose(),
            Field::Activation,
            true,
            enabled,
        ))
        .push(
            pick_list(
                [Mode::Automatic, Mode::Hotp, Mode::Totp],
                Some(state.authenticator.mode),
                |value| event(Event::Mode(value)),
            )
            .placeholder("Duo passcode mode")
            .padding(10),
        )
        .push(toggle(
            "Replace existing enrollment when enrolling Push & passcodes",
            state.authenticator.replace_duo,
            Toggle::ReplaceDuo,
            enabled,
        ))
        .push(
            row![
                action("Enroll Duo Push & passcodes", Action::EnrollDuo, writes),
                action("Enroll Duo passcodes only", Action::EnrollPasscodes, writes),
                action("Remove Duo Push", Action::RemoveDuo, writes && item.has_duo)
                    .style(button_style::danger),
            ]
            .spacing(8)
            .wrap(),
        )
        .push(
            text(
                "Removing Duo Push keeps its passcodes. Remove the authenticator separately to \
                 remove passcodes. These changes take effect after confirmation.",
            )
            .size(14),
        );
    if state
        .prepared
        .as_ref()
        .is_some_and(|prepared| prepared.action.edits_authenticator())
    {
        form = form.push(confirmation(state, app));
    }
    form
}

pub(super) fn view<'a>(state: &'a State, app: &'a App) -> Element<'a, AppMessage> {
    let enabled = !app.busy();
    let unlocked = enabled && app.connection.running && app.connection.session.is_some();
    let writes = unlocked && app.recovery.id().is_none();
    let server_writes = enabled && app.connection.running && app.recovery.id().is_none();
    let choices: Vec<Choice> = app
        .items
        .iter()
        .map(|item| Choice {
            id: item.id,
            label: format!("{} · {}", item.id, item.name),
        })
        .collect();
    if state.section == Section::Overview {
        return overview(app);
    }
    let header = row![
        styles::action(
            "All tools",
            event(Event::Section(Section::Overview)),
            enabled
        ),
        text(if state.section == Section::Files {
            state.files.file_operation.to_string()
        } else {
            state.section.to_string()
        })
        .size(25),
    ]
    .spacing(14)
    .align_y(iced::Alignment::Center)
    .wrap();
    let mut frame = column![header].spacing(14).height(Fill);
    if state
        .prepared
        .as_ref()
        .is_some_and(|prepared| !matches!(prepared.action, Action::Respond(..)))
    {
        frame = frame.push(
            scrollable(confirmation(state, app))
                .id("vault-tools")
                .height(Fill),
        );
        return container(styles::panel(frame).max_width(900).height(Fill))
            .center_x(Fill)
            .height(Fill)
            .into();
    }
    if state.show_results && state.result.is_some() {
        frame = frame.push(results(state, app));
        return container(styles::panel(frame).max_width(900).height(Fill))
            .center_x(Fill)
            .height(Fill)
            .into();
    }
    if state.result.is_some() {
        frame = frame.push(styles::action(
            "View last result",
            event(Event::ShowResults(true)),
            enabled,
        ));
    }
    let mut form = column![].spacing(16);
    if state.section == Section::Recovery {
        form = form.push(text("Item for password history").size(14)).push(
            pick_list(choices, state.selected.clone(), |value| {
                event(Event::Select(value))
            })
            .placeholder("Item for password history")
            .padding(10)
            .width(Fill),
        );
    }
    if app.connection.session.is_none()
        && !matches!(state.section, Section::Browser | Section::Utilities)
    {
        form = form.push(
            text(
                "Unlock a vault to use item tools. Creating a vault, restoring a backup, and \
                 importing into a new vault are available while locked.",
            )
            .size(14),
        );
    }
    form = match state.section {
        Section::Overview => unreachable!(),
        Section::Recovery => recovery_form(form, unlocked),
        Section::Trash => trash_form(form, unlocked),
        Section::Audit => audit_form(state, form, enabled, unlocked),
        Section::Files => files_form(state, app, form, enabled, writes, server_writes),
        Section::Security => security_form(state, app, form, enabled, writes, server_writes),
        Section::Search => search_form(state, form, enabled, unlocked),
        Section::Utilities => utilities_form(state, app, form, enabled),
        Section::Browser => browser_form(state, form, enabled),
    };
    frame = frame.push(scrollable(form).spacing(12).id("vault-tools").height(Fill));
    container(styles::panel(frame).max_width(900).height(Fill))
        .center_x(Fill)
        .height(Fill)
        .into()
}

/// Password history for the selected item.
fn recovery_form<'a>(form: Column<'a, AppMessage>, unlocked: bool) -> Column<'a, AppMessage> {
    form.push(
        text("Review an item's previous passwords and restore a revision when needed.").size(16),
    )
    .push(action("Load password history", Action::History, unlocked))
}

/// Deleted items.
fn trash_form<'a>(form: Column<'a, AppMessage>, unlocked: bool) -> Column<'a, AppMessage> {
    form.push(
        text(
            "Deleted items stay encrypted in your vault until you restore or permanently \
             erase them.",
        )
        .size(16),
    )
    .push(action("Load deleted items", Action::Trash, unlocked))
}

/// Vault health options.
fn audit_form<'a>(
    state: &'a State,
    form: Column<'a, AppMessage>,
    enabled: bool,
    unlocked: bool,
) -> Column<'a, AppMessage> {
    form.push(
        text(
            "Find weak, reused, or exposed passwords and open an affected item directly \
             from the results.",
        )
        .size(16),
    )
    .push(field(
        "Passwords at least this many days old (optional)",
        &state.audit.stale_days,
        Field::StaleDays,
        false,
        enabled,
    ))
    .push(toggle(
        "Report logins missing an authenticator",
        state.audit.require_otp,
        Toggle::RequireOtp,
        enabled,
    ))
    .push(toggle(
        "Check Pwned Passwords using hash prefixes (network request)",
        state.audit.breaches,
        Toggle::Breaches,
        enabled,
    ))
    .push(action("Check vault health", Action::Audit, unlocked))
}

/// Backup, restore, import, and export.
fn files_form<'a>(
    state: &'a State,
    app: &'a App,
    form: Column<'a, AppMessage>,
    enabled: bool,
    writes: bool,
    server_writes: bool,
) -> Column<'a, AppMessage> {
    let saving = matches!(
        state.files.file_operation,
        FileOperation::Backup | FileOperation::Export
    );
    let operation = match state.files.file_operation {
        FileOperation::Backup => Action::Backup,
        FileOperation::Restore => Action::RestoreBackup,
        FileOperation::Import => Action::Import,
        FileOperation::Export => Action::Export,
    };
    let readiness = state.prepare(operation, app);
    let file_ready = readiness.is_ok();
    let preview_ready = state.prepare(Action::PreviewImport, app).is_ok();
    let mut form = form.push(path(
        "File",
        &state.files.path,
        Field::Path,
        saving,
        enabled,
    ));
    if let Err(message) = readiness {
        form = form.push(text(message).size(14).style(text::danger));
    }
    match state.files.file_operation {
        FileOperation::Backup => {
            // Backups use an existing key; only password backups need confirmation.
            form = form.push(credentials(state, false, enabled));
            if !state.credentials.use_key {
                form = form.push(field(
                    "Confirm backup password",
                    state.credentials.confirmation.expose(),
                    Field::Confirmation,
                    true,
                    enabled,
                ));
            }
            form.push(toggle(
                "Replace an existing backup file",
                state.files.force,
                Toggle::Force,
                enabled,
            ))
            .push(action(
                "Create encrypted backup",
                Action::Backup,
                writes && file_ready,
            ))
        }
        FileOperation::Restore => form
            .push(text("Restores a separate locked vault. Lock the current vault first.").size(14))
            .push(credentials(state, false, enabled))
            .push(action(
                "Restore backup",
                Action::RestoreBackup,
                server_writes && app.connection.session.is_none() && file_ready,
            )),
        FileOperation::Import => {
            form = form
                .push(
                    text(
                        "Supports CSV, JSON, Bitwarden JSON, and portable JSON. Preview \
                         counts, conflicts, and data loss before importing.",
                    )
                    .size(14),
                )
                .push(
                    pick_list(
                        [Policy::Skip, Policy::Replace, Policy::KeepBoth],
                        Some(state.files.policy),
                        |value| event(Event::Policy(value)),
                    )
                    .placeholder("Import duplicate policy")
                    .padding(10),
                )
                .push(toggle(
                    "Import into a new vault",
                    state.files.import_new,
                    Toggle::ImportNew,
                    enabled,
                ));
            if state.files.import_new {
                form = form.push(credentials(state, true, enabled));
            }
            form.push(
                row![
                    action(
                        "Preview import",
                        Action::PreviewImport,
                        server_writes && preview_ready
                    ),
                    action("Import", Action::Import, server_writes && file_ready)
                ]
                .spacing(10)
                .wrap(),
            )
        }
        FileOperation::Export => form
            .push(
                text(
                    "Exports plaintext secrets. Use .json to preserve rich metadata; \
                     other extensions produce CSV. Prefer an encrypted backup for \
                     safekeeping.",
                )
                .size(14),
            )
            .push(toggle(
                "Replace an existing export file",
                state.files.force,
                Toggle::Force,
                enabled,
            ))
            .push(action(
                "Export plaintext",
                Action::Export,
                writes && file_ready,
            )),
    }
}

/// Credential changes and vault lifecycle.
fn security_form<'a>(
    state: &'a State,
    app: &'a App,
    mut form: Column<'a, AppMessage>,
    enabled: bool,
    writes: bool,
    server_writes: bool,
) -> Column<'a, AppMessage> {
    let operation = match state.credentials.vault_operation {
        VaultOperation::Rekey => Action::Rekey,
        VaultOperation::Create => Action::NewVault,
        VaultOperation::Delete => Action::DeleteVault,
    };
    let readiness = state.prepare(operation, app);
    let credentials_ready = readiness.is_ok();
    if let Err(message) = readiness {
        form = form.push(text(message).size(14).style(text::danger));
    }
    form.push(text("Vault credentials").size(19))
        .push(
            text(
                "New vaults and rekeying create a new external key when key mode is \
                 selected. Deleting a vault authenticates using its existing credentials. \
                 Select the vault on the Vault tab.",
            )
            .size(14),
        )
        .push(
            pick_list(
                [
                    VaultOperation::Rekey,
                    VaultOperation::Create,
                    VaultOperation::Delete,
                ],
                Some(state.credentials.vault_operation),
                |value| event(Event::VaultOperation(value)),
            )
            .placeholder("Vault operation")
            .padding(10),
        )
        .push(credentials(
            state,
            state.credentials.vault_operation != VaultOperation::Delete,
            enabled,
        ))
        .push(toggle(
            "Keep the external key when deleting a vault",
            state.credentials.keep_key,
            Toggle::KeepKey,
            enabled,
        ))
        .push(match state.credentials.vault_operation {
            VaultOperation::Rekey => action(
                "Change vault credentials",
                Action::Rekey,
                writes && credentials_ready,
            ),
            VaultOperation::Create => action(
                "Create vault",
                Action::NewVault,
                server_writes && credentials_ready,
            ),
            VaultOperation::Delete => action(
                "Delete selected vault",
                Action::DeleteVault,
                server_writes && app.connection.session.is_none() && credentials_ready,
            )
            .style(button_style::danger),
        })
}

/// Advanced item search.
fn search_form<'a>(
    state: &'a State,
    form: Column<'a, AppMessage>,
    enabled: bool,
    unlocked: bool,
) -> Column<'a, AppMessage> {
    let mut kinds = vec!["All types".to_owned()];
    kinds.extend(model::KINDS.iter().map(ToString::to_string));
    let selected = state
        .search
        .kind
        .map(|kind| kind.to_string())
        .unwrap_or_else(|| "All types".into());
    let mut form = form.push(text("Search metadata, notes, and non-secret custom fields").size(18));
    for (label, value, key) in [
        (
            "Any matching text",
            state.search.query.as_str(),
            Field::Query,
        ),
        ("Name contains", state.search.name.as_str(), Field::Name),
        (
            "Username contains",
            state.search.username.as_str(),
            Field::Username,
        ),
        ("URL contains", state.search.url.as_str(), Field::Url),
        ("Notes contain", state.search.notes.expose(), Field::Notes),
        (
            "Passwords at least this many days old (optional)",
            state.audit.stale_days.as_str(),
            Field::StaleDays,
        ),
    ] {
        form = form.push(field(
            label,
            value,
            key,
            matches!(key, Field::Notes),
            enabled,
        ));
    }
    form.push(
        pick_list(kinds, Some(selected), |value| {
            event(Event::Kind(
                model::KINDS
                    .iter()
                    .find(|kind| kind.to_string() == value)
                    .copied(),
            ))
        })
        .placeholder("Filter item type")
        .padding(10),
    )
    .push(
        pick_list(
            [
                "Any authenticator",
                "With authenticator",
                "Without authenticator",
            ],
            Some(match state.search.has_otp {
                None => "Any authenticator",
                Some(true) => "With authenticator",
                Some(false) => "Without authenticator",
            }),
            |value| {
                event(Event::HasOtp(match value {
                    "With authenticator" => Some(true),
                    "Without authenticator" => Some(false),
                    _ => None,
                }))
            },
        )
        .placeholder("Filter authenticator")
        .padding(10),
    )
    .push(
        pick_list(
            ["ID", "Name", "Created", "Modified", "Password age"],
            Some(match state.search.sort {
                SortField::Id => "ID",
                SortField::Name => "Name",
                SortField::Created => "Created",
                SortField::Modified => "Modified",
                SortField::PasswordAge => "Password age",
            }),
            |value| {
                event(Event::Sort(match value {
                    "Name" => SortField::Name,
                    "Created" => SortField::Created,
                    "Modified" => SortField::Modified,
                    "Password age" => SortField::PasswordAge,
                    _ => SortField::Id,
                }))
            },
        )
        .placeholder("Sort search results")
        .padding(10),
    )
    .push(toggle(
        "Only weak primary secrets",
        state.search.weak,
        Toggle::Weak,
        enabled,
    ))
    .push(toggle(
        "Descending order",
        state.search.descending,
        Toggle::Descending,
        enabled,
    ))
    .push(action("Search vault", Action::Search, unlocked))
}

/// Operation lookup and shell completions.
fn utilities_form<'a>(
    state: &'a State,
    app: &'a App,
    form: Column<'a, AppMessage>,
    enabled: bool,
) -> Column<'a, AppMessage> {
    form.push(text("Inspect a previous operation").size(19))
        .push(
            text(
                "Enter an operation ID reported by the CLI or another client. Checking its \
             outcome never retries it or clears this window's pending changes.",
            )
            .size(14),
        )
        .push(field(
            "Operation ID",
            &state.utilities.operation_id,
            Field::OperationId,
            false,
            enabled,
        ))
        .push(action(
            "Check operation outcome",
            Action::OperationStatus,
            enabled
                && app.connection.running
                && state.prepare(Action::OperationStatus, app).is_ok(),
        ))
        .push(rule::horizontal(1))
        .push(text("Save shell completions").size(19))
        .push(
            pick_list(
                [
                    clap_complete::Shell::Bash,
                    clap_complete::Shell::Elvish,
                    clap_complete::Shell::Fish,
                    clap_complete::Shell::PowerShell,
                    clap_complete::Shell::Zsh,
                ],
                Some(state.utilities.shell),
                |shell| event(Event::Shell(shell)),
            )
            .padding(10),
        )
        .push(path(
            "Completion file (must not already exist)",
            &state.files.path,
            Field::Path,
            true,
            enabled,
        ))
        .push(action(
            "Save shell completions",
            Action::Completions,
            enabled && !state.files.path.trim().is_empty(),
        ))
}

/// Browser extension connection.
fn browser_form<'a>(
    state: &'a State,
    form: Column<'a, AppMessage>,
    enabled: bool,
) -> Column<'a, AppMessage> {
    form.push(text("Register the browser extension").size(19))
        .push(
            text(
                "Load extension/ as an unpacked extension first, then enter its ID. Reload \
             the extension afterward. On Windows, fully close the browser before \
             installing or updating its native host.",
            )
            .size(14),
        )
        .push(
            pick_list(
                [Browser::Chrome, Browser::Chromium, Browser::Helium],
                Some(state.browser.browser),
                |value| event(Event::Browser(value)),
            )
            .placeholder("Browser to register")
            .padding(10),
        )
        .push(field(
            "32-character extension ID",
            &state.browser.extension_id,
            Field::ExtensionId,
            false,
            enabled,
        ))
        .push(
            row![
                action("Register browser bridge", Action::InstallHost, enabled),
                action("Update registered bridge", Action::UpdateHost, enabled),
            ]
            .spacing(10)
            .wrap(),
        )
        .push(action(
            "Install application-menu shortcut (Linux)",
            Action::Shortcut,
            enabled && cfg!(target_os = "linux"),
        ))
}

fn results<'a>(state: &'a State, app: &'a App) -> Element<'a, AppMessage> {
    let enabled = !app.busy();
    let writes = enabled && app.connection.session.is_some() && app.recovery.id().is_none();
    let result = state.result.as_ref().unwrap();
    let window = presentation::Page::new(state.result_page, state.result_count());
    let mut form = column![].spacing(14);
    match result {
        ResponsePayload::History(_) if state.history_for(app).is_none() => {
            form = form.push(text(
                "Reload password history for the selected item before restoring.",
            ));
        }
        ResponsePayload::History(page) => {
            if page.history.is_empty() {
                form = form.push(text("No saved password revisions."));
            }
            for (index, changed) in page
                .history
                .iter()
                .enumerate()
                .skip(window.range.start)
                .take(presentation::PAGE_SIZE)
            {
                form = form.push(
                    row![
                        text(format!(
                            "Revision {} · {}",
                            index + 1,
                            crate::gui::presentation::display_date(changed)
                        ))
                        .width(Fill),
                        action(
                            "Restore password",
                            Action::RestorePassword(index + 1),
                            writes
                        )
                    ]
                    .spacing(10),
                );
            }
        }
        ResponsePayload::Trash(page) => {
            for entry in &page.trash[window.range.clone()] {
                form = form.push(
                    column![
                        text(trash_label(entry)),
                        row![
                            action("Restore", Action::RestoreTrash(entry.id), writes),
                            action("Erase permanently…", Action::Purge(Some(entry.id)), writes)
                                .style(quiet_danger)
                        ]
                        .spacing(10)
                    ]
                    .spacing(8),
                );
            }
            if page.trash.is_empty() {
                form = form.push(text("Trash is empty."));
            } else {
                form = form.push(
                    action("Empty trash permanently…", Action::Purge(None), writes)
                        .style(quiet_danger),
                );
            }
        }
        ResponsePayload::ItemPage(page) => {
            form = form.push(text(format!("{} matching items", page.total)));
            for item in &page.items[window.range.clone()] {
                form = form.push(
                    button(text(format!(
                        "{} · {}",
                        item.name,
                        item.username.as_deref().unwrap_or("")
                    )))
                    .padding(10)
                    .on_press_maybe(enabled.then_some(AppMessage::OpenToolItem(item.id))),
                );
            }
        }
        ResponsePayload::Audit(report) => {
            let (heading, detail) = audit_summary(report);
            form = form
                .push(text(heading).size(25))
                .push(text(detail).size(16));
            // One heading per finding group; rows carry only per-item detail.
            let mut heading = None;
            for (entry, finding) in audit_rows(report)
                .skip(window.range.start)
                .take(presentation::PAGE_SIZE)
            {
                let title = finding.title();
                if heading.as_ref() != Some(&title) {
                    form = form.push(text(title.clone()).size(19));
                    heading = Some(title);
                }
                let mut detail = entry
                    .username
                    .as_deref()
                    .filter(|username| !username.is_empty())
                    .map(str::to_owned)
                    .into_iter()
                    .chain(finding.detail())
                    .collect::<Vec<_>>();
                detail.push("Open to fix".into());
                form = form.push(
                    button(
                        column![
                            text(&entry.name).size(16),
                            text(detail.join(" · ")).size(13)
                        ]
                        .spacing(3),
                    )
                    .padding(12)
                    .width(Fill)
                    .style(quiet_button)
                    .on_press_maybe(enabled.then_some(AppMessage::OpenToolItem(entry.id))),
                );
            }
            if let Some(message) = &report.breach_error {
                form = form
                    .push(text(format!("Breach check incomplete: {message}")).style(text::danger));
            }
        }
        // Secrets render from the borrowed protected value: building a String
        // here would leave an unwiped copy behind on every redraw.
        ResponsePayload::Secret(secret) => form = form.push(text(secret.expose()).size(16)),
        ResponsePayload::Authenticator(code) => {
            form = form
                .push(
                    row![
                        text(code.mode.to_uppercase()).size(16),
                        text(code.code.expose()).size(16)
                    ]
                    .spacing(8),
                )
                .push(text(authenticator_detail(code)).size(16));
        }
        _ => form = form.push(text(report(result)).size(16)),
    }

    let mut navigation = column![].spacing(8);
    if window.pages > 1 {
        navigation = navigation
            .push(
                text(format!(
                    "Page {} of {} · {} per page",
                    window.index + 1,
                    window.pages,
                    presentation::PAGE_SIZE
                ))
                .size(13),
            )
            .push(
                row![
                    button("Previous page").padding([7, 8]).on_press_maybe(
                        (enabled && window.index > 0)
                            .then_some(event(Event::ResultPage(window.index.saturating_sub(1))))
                    ),
                    button("Next page").padding([7, 8]).on_press_maybe(
                        (enabled && window.index + 1 < window.pages)
                            .then_some(event(Event::ResultPage(window.index + 1)))
                    ),
                ]
                .spacing(8)
                .wrap(),
            );
    }
    column![
        scrollable(form).spacing(12).id("vault-tools").height(Fill),
        navigation,
        rule::horizontal(1),
        row![
            styles::action("Back to options", event(Event::ShowResults(false)), enabled),
            styles::action("Clear result", event(Event::ClearResult), true),
            styles::action("View your items", AppMessage::Tab(Tab::Vault), enabled),
        ]
        .spacing(10)
        .wrap(),
    ]
    .spacing(14)
    .height(Fill)
    .into()
}

#[derive(Clone, Copy)]
enum AuditFinding {
    Category(&'static str),
    Group(&'static str, usize),
    Breached(u64),
}
impl AuditFinding {
    fn title(self) -> String {
        match self {
            Self::Category(title) => title.into(),
            Self::Group(title, group) => format!("{title} · group {group}"),
            Self::Breached(_) => "Exposed passwords".into(),
        }
    }
    fn detail(self) -> Option<String> {
        match self {
            Self::Breached(count) => Some(format!("seen {count} times in breaches")),
            _ => None,
        }
    }
}
fn audit_rows(
    report: &password_manager::vault::AuditReport,
) -> impl Iterator<Item = (&password_manager::vault::AuditLabel, AuditFinding)> {
    [
        ("Weak passwords", report.weak.as_slice()),
        ("Old passwords", report.stale.as_slice()),
        ("Missing authenticators", report.missing_totp.as_slice()),
        ("Breach check incomplete", report.unchecked.as_slice()),
    ]
    .into_iter()
    .flat_map(|(title, entries)| {
        entries
            .iter()
            .map(move |entry| (entry, AuditFinding::Category(title)))
    })
    .chain(
        [
            ("Reused passwords", &report.reused),
            ("Duplicate logins", &report.duplicates),
        ]
        .into_iter()
        .flat_map(|(title, groups)| {
            groups.iter().enumerate().flat_map(move |(index, group)| {
                group
                    .iter()
                    .map(move |entry| (entry, AuditFinding::Group(title, index + 1)))
            })
        }),
    )
    .chain(
        report
            .breached
            .iter()
            .map(|(entry, count)| (entry, AuditFinding::Breached(*count))),
    )
}

fn overview(app: &App) -> Element<'_, AppMessage> {
    let card = |title: &'static str, description: &'static str, value: Event| {
        button(column![text(title).size(17), text(description).size(14)].spacing(6))
            .padding(12)
            .width(iced::Length::Fixed(if app.compact() {
                (app.ui.width - 72.0).min(760.0)
            } else {
                195.0
            }))
            .style(quiet_button)
            .on_press_maybe((!app.busy()).then_some(event(value)))
    };
    let recovery = row![
        card(
            "Vault health",
            "Find weak, reused, and exposed passwords.",
            Event::Section(Section::Audit)
        ),
        card(
            "Deleted items",
            "Restore an item or empty encrypted trash.",
            Event::Section(Section::Trash)
        ),
        card(
            "Password history",
            "Recover a previous password for an item.",
            Event::Section(Section::Recovery)
        ),
    ]
    .spacing(12)
    .wrap();
    let files = row![
        card(
            "Encrypted backup",
            "Save a complete encrypted copy of your vault.",
            Event::FileOperation(FileOperation::Backup)
        ),
        card(
            "Restore a backup",
            "Recover a separate vault from an encrypted backup.",
            Event::FileOperation(FileOperation::Restore)
        ),
        card(
            "Import items",
            "Bring passwords from another manager.",
            Event::FileOperation(FileOperation::Import)
        ),
        card(
            "Export items",
            "Create a portable plaintext export.",
            Event::FileOperation(FileOperation::Export)
        ),
    ]
    .spacing(12)
    .wrap();
    let advanced = row![
        card(
            "CLI utilities",
            "Look up an operation or save shell completions.",
            Event::Section(Section::Utilities)
        ),
        card(
            "Advanced search",
            "Search notes, fields, types, and password age.",
            Event::Section(Section::Search)
        ),
        card(
            "Vault security",
            "Change credentials or manage a vault.",
            Event::Section(Section::Security)
        ),
        card(
            "Browser connection",
            "Connect your browser extension.",
            Event::Section(Section::Browser)
        ),
    ]
    .spacing(12)
    .wrap();
    let content = column![
        row![text("Tools").size(27), text("Choose a task").size(16)]
            .spacing(16)
            .align_y(iced::Alignment::Center),
        text("Security & recovery").size(20),
        recovery,
        text("Move & protect your data").size(20),
        files,
        text("More tools").size(20),
        advanced,
    ]
    .spacing(12);
    container(
        container(scrollable(content).id("vault-tools").spacing(12))
            .max_width(850)
            .height(Fill),
    )
    .center_x(Fill)
    .height(Fill)
    .into()
}

fn authenticator_detail(code: &password_manager::protocol::AuthenticatorResponse) -> String {
    code.counter
        .map(|counter| format!("Counter {counter}; the next counter has been saved."))
        .unwrap_or_else(|| {
            format!(
                "{} seconds remaining at retrieval.",
                code.expires_in.unwrap_or_default()
            )
        })
}

/// Plain-text summary of a non-secret result. Secret and one-time-code results
/// are rendered by [`results`] directly from their protected values, so this
/// never copies them into an ordinary `String`.
pub(super) fn report(payload: &ResponsePayload) -> String {
    match payload {
        ResponsePayload::Operation(receipt) => format!(
            "Operation {}\nState: {}{}",
            receipt.operation_id,
            match receipt.state {
                password_manager::protocol::OperationState::Committed => "Committed",
                password_manager::protocol::OperationState::Failed => "Failed",
                password_manager::protocol::OperationState::Pending =>
                    "Pending — check again before making another change",
                password_manager::protocol::OperationState::Unknown =>
                    "Unknown — inspect the vault before deciding on a new change",
                password_manager::protocol::OperationState::CommittedDurabilityUnknown =>
                    "Committed, durability uncertain — inspect the vault before deciding on a new \
                     change",
            },
            receipt
                .revision
                .map(|revision| format!("\nRevision: {revision}"))
                .unwrap_or_default()
        ),
        ResponsePayload::Message(message) => message.clone(),
        ResponsePayload::Vault(reference) => format!(
            "Restored vault: {}\nUnlock it using the backup password or key.",
            reference.vault_file
        ),
        ResponsePayload::ImportReport(report) => format!(
            "{}: {} records\nAdded: {} · Replaced: {} · Skipped: {} · Renamed: {}\nUnsupported \
             records: {} · Data-loss findings: {}\n{}",
            if report.preview {
                "Import preview"
            } else {
                "Import complete"
            },
            report.total,
            report.added,
            report.replaced,
            report.skipped,
            report.renamed,
            report.unsupported,
            report.loss_count,
            report.losses.join("\n")
        ),
        ResponsePayload::Audit(report) => {
            let (heading, detail) = audit_summary(report);
            let mut output = format!("{heading}\n{detail}\n");
            for (name, entries) in [
                ("Weak password", &report.weak),
                ("Stale password", &report.stale),
                ("Missing authenticator", &report.missing_totp),
                ("Breach check incomplete", &report.unchecked),
            ] {
                for entry in entries {
                    output.push_str(&format!("\n{name}: {} · {}", entry.id, entry.name));
                    if name == "Weak password" {
                        output.push_str(&format!(
                            " · username: {}",
                            entry.username.as_deref().unwrap_or("(none)")
                        ));
                    } else if name == "Stale password" {
                        output.push_str(&format!(" (last changed {})", entry.password_changed));
                    }
                }
            }
            for (name, groups) in [
                ("Reused password", &report.reused),
                ("Duplicate login", &report.duplicates),
            ] {
                for group in groups {
                    output.push_str(&format!(
                        "\n{name}: {}",
                        group
                            .iter()
                            .map(|entry| format!("{} · {}", entry.id, entry.name))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
            for (entry, count) in &report.breached {
                output.push_str(&format!(
                    "\nBreached password: {} · {} (seen {count} times)",
                    entry.id, entry.name
                ));
            }
            if let Some(error) = &report.breach_error {
                output.push_str(&format!("\nBreach check unavailable: {error}"));
            }
            output
        }
        _ => "Operation completed.".into(),
    }
}

pub(super) fn audit_summary(report: &password_manager::vault::AuditReport) -> (String, String) {
    if report.total == 0 {
        (
            "No login items to assess".into(),
            "Vault health checks login passwords. Add a login item to get an assessment.".into(),
        )
    } else {
        (
            format!("Vault health · {}/100", report.score),
            format!(
                "{} of {} login items have no detected issues.",
                report.healthy, report.total
            ),
        )
    }
}

fn expiry(seconds: u64) -> String {
    i64::try_from(seconds)
        .ok()
        .and_then(|value| jiff::Timestamp::from_second(value).ok())
        .map(|value| {
            value
                .to_zoned(jiff::tz::TimeZone::system())
                .strftime("%Y-%m-%d %H:%M:%S %Z")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".into())
}

pub(super) fn trash_label(entry: &password_manager::vault::TrashSummary) -> String {
    format!(
        "{} · {} · Deleted {}",
        entry.name,
        crate::gui::model::profile(entry.kind).title,
        crate::gui::presentation::display_date(&entry.deleted)
    )
}
