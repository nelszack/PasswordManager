use super::*;
use crate::gui::Message as AppMessage;
use iced::{
    Fill,
    widget::{
        Column, button, checkbox, column, container, pick_list, row, rule, scrollable, text,
        text_input,
    },
};

fn event(value: Event) -> AppMessage {
    AppMessage::Workflow(value)
}
fn action<'a>(
    label: &'a str,
    value: Action,
    enabled: bool,
) -> iced::widget::Button<'a, AppMessage> {
    button(label)
        .padding([9, 14])
        .on_press_maybe(enabled.then_some(event(Event::Run(value))))
}
fn field<'a>(
    label: &'a str,
    value: &'a str,
    key: Field,
    secret: bool,
    enabled: bool,
) -> Element<'a, AppMessage> {
    column![
        text(label).size(13),
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
        text(label).size(13),
        row![
            text_input("Choose or enter a file path", value)
                .padding(10)
                .on_input_maybe(
                    enabled.then_some(move |value: String| event(Event::Field(key, value.into())))
                ),
            button("Browse…")
                .padding([9, 14])
                .on_press_maybe(enabled.then_some(event(Event::Pick(key, save))))
        ]
        .spacing(8)
    ]
    .spacing(6)
    .into()
}
fn credentials<'a>(state: &'a State, new: bool, enabled: bool) -> Column<'a, AppMessage> {
    let mut form = column![toggle(
        "Use an external key file",
        state.use_key,
        Toggle::UseKey,
        enabled
    )]
    .spacing(12);
    if state.use_key {
        form = form.push(path(
            if new {
                "New key file (must not already exist)"
            } else {
                "Existing key file"
            },
            &state.key_path,
            Field::KeyPath,
            new,
            enabled,
        ));
    } else {
        form = form.push(field(
            "Password",
            state.password.expose(),
            Field::Password,
            true,
            enabled,
        ));
        if new {
            form = form.push(field(
                "Confirm password",
                state.confirmation.expose(),
                Field::Confirmation,
                true,
                enabled,
            ));
        }
    }
    form
}

pub(super) fn confirmation<'a>(state: &'a State, app: &'a App) -> Column<'a, AppMessage> {
    let enabled = !app.busy;
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
                    button("Cancel")
                        .padding([9, 14])
                        .on_press_maybe(enabled.then_some(event(Event::Cancel))),
                    button("Confirm")
                        .padding([9, 14])
                        .style(button::danger)
                        .on_press_maybe(
                            (enabled && app.pending.is_none()).then_some(event(Event::Confirm))
                        ),
                ]
                .spacing(10),
            );
    }
    form
}

fn duo_options<'a>(state: &'a State, app: &'a App) -> Column<'a, AppMessage> {
    let mut form = column![].spacing(12);
    if !state.watch_duo
        || !state.duo_watch_target.as_ref().is_some_and(|target| {
            state
                .selected
                .as_ref()
                .is_some_and(|choice| choice.id == target.choice.id)
        })
    {
        return form;
    }
    form = form
        .push(field(
            "Duo refresh interval (3–60 seconds)",
            &state.duo_interval,
            Field::DuoInterval,
            false,
            !app.busy,
        ))
        .push(toggle(
            "Show private desktop alerts for new Duo requests",
            state.notify_duo,
            Toggle::NotifyDuo,
            !app.busy,
        ));
    if let Err(error) = state.duo_interval_seconds() {
        form = form.push(text(error).size(12));
    }
    if let Some(target) = state.duo_watch_target.as_ref().filter(|_| state.watch_duo) {
        form = form.push(
            text(format!(
                "Watching {}. Review each request here before responding.",
                target.choice
            ))
            .size(12),
        );
    }
    form
}

fn duo_requests<'a>(state: &'a State, app: &'a App) -> Column<'a, AppMessage> {
    let enrolled = state.selected.as_ref().is_some_and(|choice| {
        app.items
            .iter()
            .any(|item| item.id == choice.id && item.has_duo)
    });
    let unlocked = !app.busy && app.running && app.session.is_some() && enrolled;
    let writes = unlocked && app.pending.is_none() && state.prepared.is_none();
    let mut form = column![
        text("Duo Push requests").size(19),
        row![
            action("Fetch Push requests", Action::Requests, unlocked),
            toggle(
                "Watch Duo requests in background",
                state.watch_duo
                    && state.duo_watch_target.as_ref().is_some_and(|target| state
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
        return form.push(text("Select a Push-enrolled item to receive requests. Passcodes-only enrollment does not support Push.").size(13)).push(duo_options(state, app));
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
            .push(text(if app.polling || app.busy {
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
            .push(text("Refresh paused while you review. Fetch requests to check again.").size(12));
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
            .size(12),
        ]
        .spacing(8);
        if let Some(digits) = request.code_digits {
            card = card
                .push(field(
                    "Verified Push code from the login page",
                    state.code.expose(),
                    Field::Code,
                    true,
                    unlocked,
                ))
                .push(
                    text(format!(
                        "Enter the {digits}-digit code shown for this request."
                    ))
                    .size(12),
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
                            .style(button::danger),
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
        let writes = app.writes_allowed() && app.session.is_some() && state.prepared.is_none();
        let copy_enabled = state.otp_copy_timeout.trim().is_empty()
            || state
                .otp_timeout(app.conf.clipboard.timeout)
                .is_ok_and(|timeout| timeout.is_some());
        let code = state.otp_result_for(app);
        form = form.push(text("One-time password").size(19)).push(
            row![
                action("Show code", Action::ShowOtp(false), writes),
                action("Copy code", Action::ShowOtp(true), writes && copy_enabled),
                button("Hide code")
                    .padding([9, 14])
                    .on_press_maybe(code.is_some().then_some(AppMessage::HideSecrets)),
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
                .size(12),
            );
        }
        form = form.push(toggle(
            "OTP options",
            state.otp_options_open,
            Toggle::OtpOptions,
            !app.busy,
        ));
        if state.otp_options_open {
            form = form
                .push(field(
                    "OTP copy timeout in seconds (0–255; blank uses clipboard setting)",
                    &state.otp_copy_timeout,
                    Field::OtpCopyTimeout,
                    false,
                    !app.busy,
                ))
                .push(
                    text(
                        state
                            .otp_timeout(app.conf.clipboard.timeout)
                            .err()
                            .unwrap_or_else(|| "Zero disables OTP copying.".into()),
                    )
                    .size(12),
                )
                .push(toggle(
                    "Copy each new time-based code once while watching",
                    state.copy_watched_otp,
                    Toggle::CopyWatchedOtp,
                    writes && copy_enabled,
                ))
                .push(toggle(
                    "Watch time-based codes",
                    state.watch_otp,
                    Toggle::WatchOtp,
                    writes,
                ));
        }
        form = form.push(text("Showing or copying HOTP consumes its next counter. Codes hide after 15 seconds or on focus loss. Watching supports TOTP only.").size(12));
    }
    form
}

pub(super) fn authenticator_editor<'a>(state: &'a State, app: &'a App) -> Column<'a, AppMessage> {
    let mut form = column![text("Authenticator & Duo").size(20)].spacing(12);
    let Some(draft) = &app.draft else {
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
                    .size(13),
            )
            .push(
                button("Save changes & continue editing")
                    .padding([9, 14])
                    .on_press_maybe(app.writes_allowed().then_some(AppMessage::SaveAndEdit)),
            );
    }
    form = form
        .push(text(if item.has_totp { "Authenticator configured" } else { "No authenticator configured" }).size(14))
        .push(field("Base32 secret or otpauth URI", state.configuration.expose(), Field::Configuration, true, enabled))
        .push(row![
            action(if item.has_totp { "Replace authenticator" } else { "Add authenticator" }, Action::SetOtp, writes),
            action("Remove authenticator", Action::RemoveOtp, writes && item.has_totp).style(button::danger),
        ].spacing(8).wrap())
        .push(rule::horizontal(1))
        .push(text(if item.has_duo { "Duo Push configured" } else { "No Duo Push enrollment" }).size(14))
        .push(field("Fresh Duo activation link", state.activation.expose(), Field::Activation, true, enabled))
        .push(pick_list([Mode::Automatic, Mode::Hotp, Mode::Totp], Some(state.mode), |value| event(Event::Mode(value)))
            .padding(10))
        .push(toggle("Replace existing enrollment when enrolling Push & passcodes", state.replace_duo, Toggle::ReplaceDuo, enabled))
        .push(row![
            action("Enroll Duo Push & passcodes", Action::EnrollDuo, writes),
            action("Enroll Duo passcodes only", Action::EnrollPasscodes, writes),
            action("Remove Duo Push", Action::RemoveDuo, writes && item.has_duo).style(button::danger),
        ].spacing(8).wrap())
        .push(text("Removing Duo Push keeps its passcodes. Remove the authenticator separately to remove passcodes. These changes take effect after confirmation.").size(12));
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
    let enabled = !app.busy;
    let unlocked = enabled && app.running && app.session.is_some();
    let writes = unlocked && app.pending.is_none();
    let server_writes = enabled && app.running && app.pending.is_none();
    let choices: Vec<Choice> = app
        .items
        .iter()
        .map(|item| Choice {
            id: item.id,
            label: format!("{} · {}", item.id, item.name),
        })
        .collect();
    let mut form = column![
        text("Vault tools").size(25),
        pick_list(Section::ALL.as_slice(), Some(state.section), |value| event(
            Event::Section(value)
        ))
        .padding(10),
    ]
    .spacing(14);
    if state.section == Section::Recovery {
        form = form.push(text("Item for password history").size(13)).push(
            pick_list(choices, state.selected.clone(), |value| {
                event(Event::Select(value))
            })
            .placeholder("Select an item")
            .padding(10)
            .width(Fill),
        );
    }
    if app.session.is_none() && state.section != Section::Browser {
        form = form.push(text("Unlock a vault to use item tools. Creating a vault, restoring a backup, and importing into a new vault are available while locked.").size(13));
    }
    form = match state.section {
        Section::Recovery => form
            .push(text("Password history & trash").size(19))
            .push(row![action("Load password history", Action::History, unlocked), action("Open trash", Action::Trash, unlocked)].spacing(10).wrap())
            .push(rule::horizontal(1))
            .push(text("Vault health audit").size(19))
            .push(field("Passwords at least this many days old (optional)", &state.stale_days, Field::StaleDays, false, enabled))
            .push(toggle("Report logins missing an authenticator", state.require_otp, Toggle::RequireOtp, enabled))
            .push(toggle("Check Pwned Passwords using hash prefixes (network request)", state.breaches, Toggle::Breaches, enabled))
            .push(action("Run audit", Action::Audit, unlocked)),
        Section::Files => {
            let operations = [FileOperation::Backup, FileOperation::Restore, FileOperation::Import, FileOperation::Export];
            let saving = matches!(state.file_operation, FileOperation::Backup | FileOperation::Export);
            let mut form = form
                .push(pick_list(operations, Some(state.file_operation), |value| event(Event::FileOperation(value))).padding(10))
                .push(path("File", &state.path, Field::Path, saving, enabled));
            match state.file_operation {
                FileOperation::Backup => {
                    // Backups use an existing key; only password backups need confirmation.
                    form = form.push(credentials(state, false, enabled));
                    if !state.use_key { form = form.push(field("Confirm backup password", state.confirmation.expose(), Field::Confirmation, true, enabled)); }
                    form.push(toggle("Replace an existing backup file", state.force, Toggle::Force, enabled))
                        .push(action("Create encrypted backup", Action::Backup, writes))
                }
                FileOperation::Restore => form
                    .push(text("Restores a separate locked vault. Lock the current vault first.").size(13))
                    .push(credentials(state, false, enabled))
                    .push(action("Restore backup", Action::RestoreBackup, server_writes && app.session.is_none())),
                FileOperation::Import => {
                    form = form
                        .push(text("Supports CSV, JSON, Bitwarden JSON, and portable JSON. Preview counts, conflicts, and data loss before importing.").size(13))
                        .push(pick_list([Policy::Skip, Policy::Replace, Policy::KeepBoth], Some(state.policy), |value| event(Event::Policy(value))).padding(10))
                        .push(toggle("Import into a new vault", state.import_new, Toggle::ImportNew, enabled));
                    if state.import_new { form = form.push(credentials(state, true, enabled)); }
                    form.push(row![
                        action("Preview import", Action::PreviewImport, server_writes && (state.import_new || app.session.is_some())),
                        action("Import", Action::Import, server_writes && (state.import_new || app.session.is_some()))
                    ].spacing(10))
                }
                FileOperation::Export => form
                    .push(text("Exports plaintext secrets. Use .json to preserve rich metadata; other extensions produce CSV. Prefer an encrypted backup for safekeeping.").size(13))
                    .push(toggle("Replace an existing export file", state.force, Toggle::Force, enabled))
                    .push(action("Export plaintext", Action::Export, writes)),
            }
        }
        Section::Security => {
            form.push(text("Vault credentials").size(19))
                .push(text("New vaults and rekeying create a new external key when key mode is selected. Deleting a vault authenticates using its existing credentials. Select the vault on the Vault tab.").size(13))
                .push(pick_list([VaultOperation::Rekey, VaultOperation::Create, VaultOperation::Delete], Some(state.vault_operation), |value| event(Event::VaultOperation(value))).padding(10))
                .push(credentials(state, state.vault_operation != VaultOperation::Delete, enabled))
                .push(toggle("Keep the external key when deleting a vault", state.keep_key, Toggle::KeepKey, enabled))
                .push(match state.vault_operation {
                    VaultOperation::Rekey => action("Change vault credentials", Action::Rekey, writes),
                    VaultOperation::Create => action("Create vault", Action::NewVault, server_writes),
                    VaultOperation::Delete => action("Delete selected vault", Action::DeleteVault, server_writes && app.session.is_none()).style(button::danger),
                })
        }
        Section::Search => {
            let mut kinds = vec!["All types".to_owned()];
            kinds.extend(model::KINDS.iter().map(ToString::to_string));
            let selected = state.kind.map(|kind| kind.to_string()).unwrap_or_else(|| "All types".into());
            let mut form = form.push(text("Search metadata, notes, and non-secret custom fields").size(18));
            for (label, value, key) in [
                ("Any matching text", state.query.as_str(), Field::Query),
                ("Name contains", state.name.as_str(), Field::Name),
                ("Username contains", state.username.as_str(), Field::Username),
                ("URL contains", state.url.as_str(), Field::Url),
                ("Notes contain", state.notes.expose(), Field::Notes),
                ("Passwords at least this many days old (optional)", state.stale_days.as_str(), Field::StaleDays),
            ] { form = form.push(field(label, value, key, matches!(key, Field::Notes), enabled)); }
            form.push(pick_list(kinds, Some(selected), |value| event(Event::Kind(model::KINDS.iter().find(|kind| kind.to_string() == value).copied()))).padding(10))
                .push(pick_list(["Any authenticator", "With authenticator", "Without authenticator"], Some(match state.has_otp { None => "Any authenticator", Some(true) => "With authenticator", Some(false) => "Without authenticator" }), |value| event(Event::HasOtp(match value { "With authenticator" => Some(true), "Without authenticator" => Some(false), _ => None }))).padding(10))
                .push(pick_list(["ID", "Name", "Created", "Modified", "Password age"], Some(match state.sort { SortField::Id => "ID", SortField::Name => "Name", SortField::Created => "Created", SortField::Modified => "Modified", SortField::PasswordAge => "Password age" }), |value| event(Event::Sort(match value { "Name" => SortField::Name, "Created" => SortField::Created, "Modified" => SortField::Modified, "Password age" => SortField::PasswordAge, _ => SortField::Id }))).padding(10))
                .push(toggle("Only weak primary secrets", state.weak, Toggle::Weak, enabled))
                .push(toggle("Descending order", state.descending, Toggle::Descending, enabled))
                .push(action("Search vault", Action::Search, unlocked))
        }
        Section::Browser => form
            .push(text("Register the browser extension").size(19))
            .push(text("Load extension/ as an unpacked extension first, then enter its ID. Reload the extension afterward. On Windows, fully close the browser before installing or updating its native host.").size(13))
            .push(pick_list([Browser::Chrome, Browser::Chromium, Browser::Helium], Some(state.browser), |value| event(Event::Browser(value))).padding(10))
            .push(field("32-character extension ID", &state.extension_id, Field::ExtensionId, false, enabled))
            .push(row![
                action("Register browser bridge", Action::InstallHost, enabled),
                action("Update registered bridge", Action::UpdateHost, enabled),
            ].spacing(10).wrap())
            .push(action("Install application-menu shortcut (Linux)", Action::Shortcut, enabled && cfg!(target_os = "linux"))),
    };
    if let Some(result) = &state.result {
        form = form.push(rule::horizontal(1)).push(
            row![
                text("Result").size(20),
                button("Clear").on_press(event(Event::ClearResult))
            ]
            .spacing(15),
        );
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
                for (index, changed) in page.history.iter().enumerate() {
                    form = form.push(
                        row![
                            text(format!("Revision {} · {changed}", index + 1)).width(Fill),
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
                for entry in &page.trash {
                    form = form.push(
                        column![
                            text(trash_label(entry)),
                            row![
                                action("Restore", Action::RestoreTrash(entry.id), writes),
                                action("Erase permanently", Action::Purge(Some(entry.id)), writes)
                                    .style(button::danger)
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
                        action("Empty trash permanently", Action::Purge(None), writes)
                            .style(button::danger),
                    );
                }
            }
            ResponsePayload::ItemPage(page) => {
                form = form.push(text(format!("{} matching items", page.total)));
                for item in &page.items {
                    form = form.push(
                        button(text(format!(
                            "{} · {} · {}",
                            item.id,
                            item.name,
                            item.username.as_deref().unwrap_or("")
                        )))
                        .padding(10)
                        .on_press_maybe(enabled.then_some(AppMessage::OpenToolItem(item.id))),
                    );
                }
            }
            _ => form = form.push(text(report(result)).size(14)),
        }
    }
    if !state
        .prepared
        .as_ref()
        .is_some_and(|prepared| matches!(prepared.action, Action::Respond(..)))
    {
        form = form.push(confirmation(state, app));
    }
    container(
        super::super::view::panel(scrollable(form).spacing(10).id("vault-tools")).max_width(900),
    )
    .center_x(Fill)
    .height(Fill)
    .into()
}

pub(super) fn report(payload: &ResponsePayload) -> String {
    match payload {
        ResponsePayload::Message(message) => message.clone(),
        ResponsePayload::Secret(secret) => secret.expose().to_owned(),
        ResponsePayload::Authenticator(code) => format!(
            "{}: {}{}",
            code.mode.to_uppercase(),
            code.code.expose(),
            code.counter
                .map(|counter| format!("\nCounter {counter}; the next counter has been saved."))
                .unwrap_or_else(|| format!(
                    "\n{} seconds remaining at retrieval.",
                    code.expires_in.unwrap_or_default()
                ))
        ),
        ResponsePayload::Vault(reference) => format!(
            "Restored vault: {}\nUnlock it using the backup password or key.",
            reference.vault_file
        ),
        ResponsePayload::ImportReport(report) => format!(
            "{}: {} records\nAdded: {} · Replaced: {} · Skipped: {} · Renamed: {}\nUnsupported records: {} · Data-loss findings: {}\n{}",
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
            let mut output = format!(
                "Health score: {}/100\n{} of {} login entries have no detected issues.\n",
                report.score, report.healthy, report.total
            );
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

fn expiry(seconds: u64) -> String {
    i64::try_from(seconds)
        .ok()
        .and_then(|value| chrono::DateTime::from_timestamp(value, 0))
        .map(|value| {
            value
                .with_timezone(&chrono::Local)
                .format("%Y-%m-%d %H:%M:%S %Z")
                .to_string()
        })
        .unwrap_or_else(|| "unknown".into())
}

pub(super) fn trash_label(entry: &password_manager::vault::TrashSummary) -> String {
    format!(
        "{} · {} [{}] · deleted {}",
        entry.id, entry.name, entry.kind, entry.deleted
    )
}
