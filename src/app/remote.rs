use super::output::Output;
use password_manager::{
    cli::{AttachmentCommands, BackupCommands, CliCommands, DeleteArgs, EntryArgs, TotpCommands},
    client, config,
    encryption::{PromptFailure, try_prompt_for_confirmed_password},
    file::{resolve_key_path, resolve_new_key_path},
    password::generate_password as make_password,
    types::{
        self, AuditOptions, BackupRequest, CustomField, EntryUpdate, ImportRequest, PasswordEntry,
        PasswordType, SearchFilter, ServerCommand, Target, TotpCommand, UnlockInfo,
    },
    vault,
};

pub(super) fn confirmed_password(console: &Output, label: &str, require_minimum: bool) -> String {
    try_prompt_for_confirmed_password(label, require_minimum, |message| {
        console.print_warning(message)
    })
    .unwrap_or_else(|failure| {
        // A rejected value is invalid input (2); a prompt that could not run is a failure (1).
        let code = match failure {
            PromptFailure::Rejected(_) => 2,
            PromptFailure::Unavailable(_) => 1,
        };
        console.exit_error(&failure.to_string(), code)
    })
}

fn hidden(console: &Output, prompt: &str, what: &str) -> String {
    password_manager::prompt::hidden(prompt, what)
        .unwrap_or_else(|error| console.exit_error(&error, 1))
}

/// The lower-case name of an item type's main secret, for prompts.
fn secret_label(kind: types::ItemKind) -> String {
    let label = password_manager::item_profile::profile(kind).secret;
    let label = label.split(" (").next().unwrap_or(label);
    if label.starts_with("API") || label.starts_with("SSH") || label.starts_with("Wi-Fi") {
        label.to_owned()
    } else {
        label.to_lowercase()
    }
}

pub(super) fn target_type(target: EntryArgs) -> Target {
    if let Some(id) = target.id {
        Target::Id(id)
    } else if let Some(name) = target.entry_name.or(target.item) {
        Target::Name(name)
    } else {
        unreachable!("clap requires a name, --id, or --entry-name")
    }
}

fn custom_fields(
    fields: Vec<String>,
    secret_fields: Vec<String>,
) -> Result<Vec<CustomField>, String> {
    let mut parsed = Vec::new();
    for field in fields {
        let (name, value) = field
            .split_once('=')
            .ok_or_else(|| format!("custom field {field:?} must use NAME=VALUE"))?;
        let name = name.trim();
        if name.is_empty() {
            return Err("custom field names cannot be empty".to_string());
        }
        parsed.retain(|existing: &CustomField| !existing.name.eq_ignore_ascii_case(name));
        parsed.push(CustomField {
            name: name.to_string(),
            value: value.to_string().into(),
            secret: false,
        });
    }
    for name in secret_fields {
        let name = name.trim();
        if name.is_empty() {
            return Err("custom field names cannot be empty".to_string());
        }
        let value = password_manager::prompt::hidden(
            &format!("{name}: "),
            &format!("custom field {name:?}"),
        )?;
        parsed.retain(|existing| !existing.name.eq_ignore_ascii_case(name));
        parsed.push(CustomField {
            name: name.to_string(),
            value: value.into(),
            secret: true,
        });
    }
    Ok(parsed)
}

fn resolved_new_key(path: String, console: &Output) -> PasswordType {
    PasswordType::Key(
        resolve_new_key_path(&path)
            .unwrap_or_else(|error| console.exit_error(&format!("invalid key path: {error}"), 2)),
    )
}

fn resolved_key(path: String, console: &Output) -> PasswordType {
    PasswordType::Key(
        resolve_key_path(&path)
            .unwrap_or_else(|error| console.exit_error(&format!("invalid key path: {error}"), 2)),
    )
}

fn resolved_file(path: String, console: &Output) -> String {
    if path.is_empty() {
        console.exit_error("file path cannot be empty", 2);
    }
    password_manager::file::absolute_unicode_path(&path)
        .map_err(|error| format!("could not resolve file path: {error}"))
        .unwrap_or_else(|error| console.exit_error(&error, 2))
}

pub(super) async fn run(
    command: CliCommands,
    conf: &config::Config,
    client: &client::AuthenticatedClient,
    console: &Output,
) {
    match command {
        CliCommands::Duo { command } => super::duo::run(command, client, console),
        CliCommands::Totp {
            command:
                TotpCommands::Show {
                    target,
                    copy,
                    copy_time,
                    watch: true,
                },
        } => {
            let result = super::totp::watch(
                client,
                target_type(target),
                copy.then_some(copy_time.unwrap_or(conf.clipboard.timeout)),
                console,
            )
            .await;
            console.finish_watch();
            if let Err(error) = result {
                console.exit_error(&error, 1);
            }
        }
        command => {
            let copies = matches!(command, CliCommands::Get { copy: true, .. });
            if copies && conf.clipboard.timeout == 0 {
                console.exit_error(
                    "Copying is turned off (clipboard timeout 0). Turn it on with `pm config \
                     --clipboard-timeout 30`, or print the value with --password-only.",
                    2,
                );
            }
            let empty_hint = empty_list_hint(&command);
            if let CliCommands::New {
                name,
                key_path,
                locked,
            } = command
            {
                super::vaults::create(client, conf, name, key_path, locked, console);
                return;
            }
            TRASH_CLIENT.with(|slot| *slot.borrow_mut() = Some(client.clone()));
            let suggest_for = match &command {
                CliCommands::Get { target, .. }
                | CliCommands::History { target }
                | CliCommands::RestorePassword { target, .. } => {
                    target.entry_name.clone().or(target.item.clone())
                }
                CliCommands::Update { target, .. } => {
                    target.entry_name.clone().or(target.item.clone())
                }
                _ => None,
            };
            // How to undo a move to trash, printed after it succeeds.
            let undo = match &command {
                CliCommands::Delete(args) if !args.vault => args
                    .entry_name
                    .clone()
                    .or(args.item.clone())
                    .map(|name| format!("Undo with `pm restore {name:?}`."))
                    .or(args
                        .id
                        .map(|id| format!("Undo with `pm restore --id {id}`."))),
                _ => None,
            };
            let reveal_notes = matches!(
                command,
                CliCommands::Get {
                    reveal_secrets: true,
                    ..
                }
            );
            let console = &console.revealing_notes(reveal_notes);
            let command = prepare_command(command, conf, console);
            if let Err(code) =
                console.send_command_with_hint(client, command, empty_hint.as_deref())
            {
                // A misspelled name: suggest close matches before exiting.
                if code == 3
                    && let Some(name) = suggest_for
                {
                    suggest_names(client, &name, console);
                }
                std::process::exit(code);
            }
            // The server reports the copy's outcome as a notice (see Output).
            let _ = copies;
            if let Some(undo) = undo {
                console.print_note(&undo);
            }
        }
    }
}

/// Weak-password checks cover logins, like `pm audit`: a card number is not a password.
fn weak_logins(mut options: types::ListOptions) -> types::ListOptions {
    if options.weak && options.kind.is_none() {
        options.kind = Some(types::ItemKind::Login);
    }
    options
}

/// "Did you mean" for a name that matched nothing.
fn suggest_names(client: &client::AuthenticatedClient, name: &str, console: &Output) {
    let needle = name.trim().to_lowercase();
    let short: String = needle.chars().take(3).collect();
    if short.is_empty() || console.is_json() {
        return;
    }
    let Ok(response) = client.request_response(ServerCommand::List(SearchFilter {
        query: Some(short),
        ..Default::default()
    })) else {
        return;
    };
    let password_manager::protocol::ResponsePayload::ItemPage(page) = response.payload else {
        return;
    };
    let mut names: Vec<_> = page.items.iter().map(|item| item.name.clone()).collect();
    // Same-named items appear once here; `pm list` shows each with its ID.
    names.sort_unstable();
    names.dedup();
    names.sort_by_key(|candidate| {
        let lower = candidate.to_lowercase();
        (
            !lower.starts_with(&needle) && !needle.starts_with(&lower),
            lower.len().abs_diff(needle.len()),
        )
    });
    names.truncate(3);
    if !names.is_empty() {
        console.print_note(&format!(
            "Did you mean: {}? Or search with `pm search {}`.",
            names
                .iter()
                .map(|n| format!(
                    "\"{}\"",
                    password_manager::client::terminal_metadata(n).as_str()
                ))
                .collect::<Vec<_>>()
                .join(", "),
            password_manager::client::terminal_metadata(name).as_str()
        ));
    }
}

/// What an empty list means for a search or filtered view, with a way forward.
fn empty_list_hint(command: &CliCommands) -> Option<String> {
    let filtered = |list: &password_manager::cli::ListArgs| {
        list.kind.is_some()
            || list.totp
            || list.no_totp
            || list.weak
            || list.stale_days.is_some()
            || !list.tags.is_empty()
            || list.favorites
    };
    match command {
        CliCommands::Search(args) => Some(match &args.query {
            Some(query) => format!(
                "No items match {:?}. Try a shorter search, or list everything with `pm view`.",
                password_manager::client::terminal_metadata(query).as_str()
            ),
            None => "No items match these filters. List everything with `pm view`.".into(),
        }),
        CliCommands::View(list) if filtered(list) => {
            Some("No items match these filters. List everything with `pm view`.".into())
        }
        _ => None,
    }
}

pub(super) fn resolve_vault(
    selected: Option<String>,
    conf: &config::Config,
    console: &Output,
) -> Option<String> {
    let vaults =
        vault::list_vaults().unwrap_or_else(|error| console.exit_error(&error.to_string(), 1));
    match selected {
        Some(wanted) => Some(
            password_manager::vault_names::Names::load()
                .resolve(&wanted, &vaults)
                .unwrap_or_else(|error| console.exit_error(&error, 2)),
        ),
        None => conf.unlock.vault_id.clone(),
    }
}

/// Fail before asking for a password when the vault to open is ambiguous.
fn require_single_vault(selected: &Option<String>, key_file: bool, console: &Output) {
    if selected.is_some() || key_file {
        return;
    }
    let vaults = vault::list_vaults().unwrap_or_default();
    if vaults.is_empty() {
        console.exit_error(
            "No vaults exist yet. Create one with `pm new --name NAME`.",
            1,
        );
    }
    if vaults.len() > 1 {
        let names = password_manager::vault_names::Names::load();
        let listed = vaults
            .iter()
            .enumerate()
            .map(|(index, id)| names.label_at(id, index, vaults.len()))
            .collect::<Vec<_>>()
            .join(", ");
        console.exit_error(
            &format!(
                "There are {} vaults ({listed}). Choose one with `pm unlock --vault NAME`, or set a \
                 default with `pm config --default-vault FILE`.",
                vaults.len()
            ),
            2,
        );
    }
}

fn prepare_command(command: CliCommands, conf: &config::Config, console: &Output) -> ServerCommand {
    match command {
        CliCommands::Operation { id } => ServerCommand::OperationStatus(id),
        CliCommands::Lock => ServerCommand::Lock(true),

        CliCommands::Unlock {
            key,
            timeout,
            vault_file,
        } => {
            let vault_file = resolve_vault(vault_file, conf, console);
            require_single_vault(&vault_file, key.is_some(), console);
            ServerCommand::Unlock(UnlockInfo {
                vault_file,
                key: if let Some(k) = key {
                    resolved_key(k, console)
                } else {
                    PasswordType::Password(hidden(console, "Master password: ", "master password"))
                },
                timeout: timeout.timeout.unwrap_or(conf.unlock.timeout),
            })
        }
        CliCommands::Status => ServerCommand::Status,
        CliCommands::SshAgent {
            command: Some(command),
        } => match command {
            password_manager::cli::SshAgentCommands::Approve { id } => {
                ServerCommand::SshDecision { id, allow: true }
            }
            password_manager::cli::SshAgentCommands::Deny { id } => {
                ServerCommand::SshDecision { id, allow: false }
            }
        },
        CliCommands::Passkey { command } => {
            use password_manager::cli::PasskeyCommands;
            let read = |prompt: &str| hidden(console, prompt, "PIN or password");
            match command {
                PasskeyCommands::Approve { id } => ServerCommand::PasskeyDecision {
                    id,
                    secret: Some(read("Master password or passkey PIN: ").into()),
                },
                PasskeyCommands::Deny { id } => ServerCommand::PasskeyDecision { id, secret: None },
                PasskeyCommands::SetPin => {
                    let pin = read("New passkey PIN: ");
                    if *zeroize::Zeroizing::new(read("Re-enter the passkey PIN: ")) != pin {
                        console.exit_error("The passkey PINs do not match.", 2);
                    }
                    ServerCommand::SetPasskeyPin(Some(pin.into()))
                }
                PasskeyCommands::RemovePin => ServerCommand::SetPasskeyPin(None),
            }
        }
        CliCommands::Kill => ServerCommand::Kill,
        CliCommands::Rekey { key_path } => ServerCommand::Rekey(if let Some(kp) = key_path {
            resolved_new_key(kp, console)
        } else {
            PasswordType::Password(confirmed_password(console, "master password", true))
        }),

        CliCommands::Add {
            name,
            username,
            url,
            kind,
            notes,
            fields,
            secret_fields,
            tags,
            favorite,
            generate_password,
            copy,
            no_copy,
        } => {
            if matches!(kind, types::ItemKind::Identity) && generate_password {
                console.exit_error("identity items do not have a primary secret to generate", 2);
            }
            let custom_fields = match custom_fields(fields, secret_fields) {
                Ok(fields) => fields,
                Err(error) => {
                    console.exit_error(&error, 2);
                }
            };
            let mut urls = url.into_iter();
            let primary_url = urls.next();
            let password = if matches!(kind, types::ItemKind::Identity) {
                String::new()
            } else if !generate_password {
                let typed = confirmed_password(console, &secret_label(kind), false);
                warn_if_weak(kind, &name, &typed, console);
                warn_if_duplicate(&name, console);
                typed
            } else {
                make_password(conf.genpass.length)
            };
            ServerCommand::Add {
                entry: types::TypedEntry {
                    entry: PasswordEntry {
                        name,
                        username,
                        password: password.into(),
                        url: primary_url,
                        notes: notes.map(Into::into),
                        copy: if !copy && !no_copy {
                            kind == types::ItemKind::Login && conf.copy.passwords
                        } else {
                            copy
                        },
                    },
                    kind,
                    additional_urls: urls.collect(),
                    custom_fields,
                    tags,
                    favorite,
                },
                copy_timeout: conf.clipboard.timeout,
            }
        }

        CliCommands::Delete(DeleteArgs {
            item,
            id,
            entry_name,
            vault,
            vault_file,
            key,
            keep_key,
            yes,
        }) => match (id, entry_name.or(item), vault) {
            (Some(i), None, _) => ServerCommand::Delete(Target::Id(i)),
            (None, Some(n), _) => ServerCommand::Delete(Target::Name(n)),
            (None, None, true) => delete_vault(vault_file, key, keep_key, yes, conf, console),
            _ => unreachable!("clap requires exactly one delete target"),
        },
        CliCommands::Vaults {
            command:
                Some(password_manager::cli::VaultsCommand::Delete {
                    vault,
                    key,
                    keep_key,
                    yes,
                }),
            ..
        } => delete_vault(vault, key, keep_key, yes, conf, console),
        CliCommands::View(options) => ServerCommand::List(SearchFilter {
            list: weak_logins(options.into()),
            ..Default::default()
        }),
        CliCommands::Search(args) => ServerCommand::List(SearchFilter {
            query: args.query,
            name: args.name,
            username: args.username,
            url: args.url,
            notes: args.notes.map(Into::into),
            list: weak_logins(args.list.into()),
        }),
        CliCommands::History { target } => ServerCommand::History(target_type(target)),
        CliCommands::Attachment { command } => ServerCommand::Attachment(match command {
            AttachmentCommands::Add { target, path, name } => types::AttachmentCommand::Add {
                target: target_type(target),
                path: resolved_file(path, console),
                name,
            },
            AttachmentCommands::Save {
                target,
                name,
                path,
                force,
            } => types::AttachmentCommand::Save {
                target: target_type(target),
                name,
                path: resolved_file(path, console),
                force,
            },
            AttachmentCommands::Remove { target, name } => types::AttachmentCommand::Remove {
                target: target_type(target),
                name,
            },
        }),
        CliCommands::RestorePassword { target, revision } => ServerCommand::RestorePassword {
            target: target_type(target),
            revision,
        },
        CliCommands::Trash => ServerCommand::Trash,
        CliCommands::Restore { id, item } => ServerCommand::RestoreTrash(match (id, item) {
            (Some(id), _) => id,
            (None, Some(name)) => trashed_id(&name, console),
            (None, None) => unreachable!("clap requires a name or --id"),
        }),
        CliCommands::Purge(args) => {
            let prompt = args.id.map_or_else(
                || "Permanently erase all trashed items?".into(),
                |id| format!("Permanently erase trashed item {id}?"),
            );
            confirm_permanent(args.yes, &prompt, console);
            ServerCommand::PurgeTrash(args.id)
        }

        CliCommands::Audit {
            stale_days,
            breaches,
            require_totp,
        } => ServerCommand::Audit(AuditOptions {
            stale_days,
            check_breaches: breaches,
            require_totp,
        }),
        CliCommands::Totp { command } => match command {
            TotpCommands::Set { target } => ServerCommand::Totp(TotpCommand::Set {
                target: target_type(target),
                configuration: hidden(
                    console,
                    "Setup key (Base32) or otpauth:// link from the site: ",
                    "authenticator setup key",
                )
                .into(),
            }),
            TotpCommands::Duo { target, mode } => ServerCommand::Totp(TotpCommand::Duo {
                target: target_type(target),
                activation: hidden(
                    console,
                    "Duo activation link (HTTPS or duo://): ",
                    "Duo activation link",
                )
                .into(),
                mode,
            }),
            TotpCommands::Show {
                target,
                copy,
                copy_time,
                watch: _,
            } => ServerCommand::Totp(TotpCommand::Show {
                target: target_type(target),
                copy_timeout: copy.then_some(copy_time.unwrap_or(conf.clipboard.timeout)),
            }),
            TotpCommands::Remove { target } => ServerCommand::Totp(TotpCommand::Remove {
                target: target_type(target),
            }),
        },
        CliCommands::Backup { command } => match command {
            BackupCommands::Create {
                path,
                key_path,
                force,
            } => ServerCommand::Backup(BackupRequest {
                path: resolved_file(path, console),
                key_pass: key_path.map_or_else(
                    || PasswordType::Password(confirmed_password(console, "backup password", true)),
                    |path| resolved_key(path, console),
                ),
                force,
            }),
            BackupCommands::Restore { path, key_path } => {
                let key_pass = key_path.map_or_else(
                    || {
                        PasswordType::Password(hidden(
                            console,
                            "Backup password: ",
                            "backup password",
                        ))
                    },
                    |path| resolved_key(path, console),
                );
                ServerCommand::RestoreBackup(BackupRequest {
                    path: resolved_file(path, console),
                    key_pass,
                    force: false,
                })
            }
        },

        CliCommands::Update {
            add,
            target,
            metadata,
        } => {
            let password = if add.generate_password {
                Some(make_password(conf.genpass.length))
            } else if add.password {
                let label = metadata
                    .kind
                    .map_or_else(|| "password".to_owned(), secret_label);
                Some(confirmed_password(console, &label, false))
            } else {
                None
            };
            let set_fields = match custom_fields(metadata.fields, metadata.secret_fields) {
                Ok(fields) => fields,
                Err(error) => {
                    console.exit_error(&error, 2);
                }
            };
            ServerCommand::Update(types::TypedUpdate {
                entry: EntryUpdate {
                    target: target_type(target),
                    password: password.map(Into::into),
                    update: add.into(),
                },
                kind: metadata.kind,
                add_url: metadata.add_url,
                remove_url: metadata.remove_url,
                clear_urls: metadata.clear_urls,
                set_fields,
                remove_fields: metadata.remove_fields,
                clear_fields: metadata.clear_fields,
                add_tags: metadata.add_tags,
                remove_tags: metadata.remove_tags,
                clear_tags: metadata.clear_tags,
                favorite: if metadata.favorite {
                    Some(true)
                } else if metadata.unfavorite {
                    Some(false)
                } else {
                    None
                },
            })
        }

        CliCommands::Get {
            target,
            password_only,
            reveal_secrets,
            field,
            copy,
        } => {
            if let Some(name) = field {
                if copy {
                    ServerCommand::GetField {
                        target: target_type(target),
                        name,
                        copy_timeout: Some(conf.clipboard.timeout),
                    }
                } else {
                    ServerCommand::GetField {
                        copy_timeout: None,
                        target: target_type(target),
                        name,
                    }
                }
            } else if password_only {
                ServerCommand::GetSecret(target_type(target))
            } else {
                ServerCommand::Get {
                    target: target_type(target),
                    // Zero asks the server for details without touching the clipboard.
                    copy_timeout: if copy { conf.clipboard.timeout } else { 0 },
                    reveal_secrets,
                }
            }
        }
        CliCommands::Export {
            path,
            format,
            force,
            yes,
        } => {
            // The extension decides the format, so a typo such as `.jsn` must not
            // silently produce a lossy CSV file.
            use password_manager::cli::ExportFormat;
            let named = std::path::Path::new(&path)
                .extension()
                .and_then(|extension| extension.to_str())
                .map(str::to_ascii_lowercase);
            let detected = match named.as_deref() {
                Some("json") => Some(ExportFormat::Json),
                Some("csv") => Some(ExportFormat::Csv),
                _ => None,
            };
            match (format, detected) {
                (_, None) => console.exit_error(
                    "Choose a file name ending in .json (portable, keeps every detail) or .csv \
                     (for other password managers).",
                    2,
                ),
                (Some(wanted), Some(found)) if wanted != found => console.exit_error(
                    &format!(
                        "--format {} does not match the file name; use a .{} file name.",
                        if wanted == ExportFormat::Json {
                            "json"
                        } else {
                            "csv"
                        },
                        if wanted == ExportFormat::Json {
                            "json"
                        } else {
                            "csv"
                        },
                    ),
                    2,
                ),
                _ => {}
            }
            let path = resolved_file(path, console);
            confirm_export(yes, &path, console);
            ServerCommand::Export { path, force }
        }

        CliCommands::Import {
            path,
            new,
            key_path,
            preview,
            conflicts,
        } => {
            if !new && key_path.is_some() {
                console.exit_error("--key can only be used together with --new", 2);
            }
            let keypass = if preview || !new {
                None
            } else {
                Some(match key_path {
                    Some(path) => resolved_new_key(path, console),
                    None => {
                        PasswordType::Password(confirmed_password(console, "master password", true))
                    }
                })
            };
            ServerCommand::Import(ImportRequest {
                path: resolved_file(path, console),
                new,
                key_pass: keypass,
                preview,
                conflicts,
                password_history_limit: conf.recovery.password_history_limit,
            })
        }
        _ => unreachable!("local commands are handled before remote dispatch"),
    }
}

/// The trash ID for a name, resolved the same way as item names elsewhere.
fn trashed_id(name: &str, console: &Output) -> usize {
    let client = TRASH_CLIENT.with(|client| client.borrow().clone());
    let Some(client) = client else {
        console.exit_error("could not read the trash", 1)
    };
    let response = client
        .request_response(ServerCommand::Trash)
        .unwrap_or_else(|error| console.exit_error(&error, 1));
    let password_manager::protocol::ResponsePayload::Trash(page) = response.payload else {
        console.exit_error(&response.error_message(), 1)
    };
    let exact: Vec<_> = page.trash.iter().filter(|item| item.name == name).collect();
    let loose: Vec<_> = page
        .trash
        .iter()
        .filter(|item| item.name.eq_ignore_ascii_case(name))
        .collect();
    match (exact.as_slice(), loose.as_slice()) {
        ([one], _) | ([], [one]) => one.id,
        ([], []) => console.exit_error(
            &format!("No trashed item is named {name:?}. See `pm trash`."),
            3,
        ),
        _ => console.exit_error(
            &format!(
                "Several trashed items are named {name:?} (IDs {}). Choose one with --id.",
                loose
                    .iter()
                    .map(|item| item.id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            2,
        ),
    }
}

thread_local! {
    /// The client for lookups made while preparing a command.
    static TRASH_CLIENT: std::cell::RefCell<Option<client::AuthenticatedClient>> =
        const { std::cell::RefCell::new(None) };
}

/// Two items with one name make every later `pm get NAME` ambiguous; say so.
fn warn_if_duplicate(name: &str, console: &Output) {
    let client = TRASH_CLIENT.with(|client| client.borrow().clone());
    let Some(client) = client else { return };
    let Ok(response) = client.request_response(ServerCommand::List(SearchFilter {
        name: Some(name.to_owned()),
        ..Default::default()
    })) else {
        return;
    };
    if let password_manager::protocol::ResponsePayload::ItemPage(page) = response.payload
        && let Some(existing) = page
            .items
            .iter()
            .find(|item| item.name.eq_ignore_ascii_case(name.trim()))
    {
        console.print_warning(&format!(
            "an item named {:?} already exists (#{}). Both are kept; refer to them by --id, or \
             rename one with `pm update --id ID --name NEW`.",
            existing.name, existing.id
        ));
    }
}

/// Warn about a weak new login password before it is saved.
fn warn_if_weak(kind: types::ItemKind, name: &str, password: &str, console: &Output) {
    if kind != types::ItemKind::Login || password.is_empty() {
        return;
    }
    let (score, rating) = password_manager::password::strength_rating(password);
    if score <= 1 {
        console.print_warning(&format!(
            "this password is weak ({rating}, {score}/4). Replace it with `pm update {:?} --generate`.",
            name
        ));
    }
}

/// A plaintext export holds every secret; ask first, as the desktop app does.
fn confirm_export(yes: bool, path: &str, console: &Output) {
    use std::io::{self, Write};
    if yes {
        return;
    }
    if !console.can_prompt() || password_manager::prompt::from_stdin() {
        console.exit_error(
            "A plaintext export contains every password. Rerun with --yes to confirm.",
            2,
        );
    }
    eprint!(
        "This writes every password in plain text to {}. Type export to continue: ",
        password_manager::client::terminal_metadata(path).as_str()
    );
    let _ = io::stderr().flush();
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() || answer.trim() != "export" {
        console.exit_error("Export canceled; nothing was written.", 2);
    }
}

/// Permanent whole-vault deletion (`pm vaults delete`, formerly `pm delete --vault`).
fn delete_vault(
    vault_file: Option<String>,
    key: Option<String>,
    keep_key: bool,
    yes: bool,
    conf: &config::Config,
    console: &Output,
) -> ServerCommand {
    let vault_file = resolve_vault(vault_file, conf, console);
    require_single_vault(&vault_file, false, console);
    let label = vault_file.as_deref().map_or_else(
        || "this vault".to_owned(),
        |id| {
            let vaults = vault::list_vaults().unwrap_or_default();
            format!(
                "the vault \"{}\"",
                password_manager::vault_names::Names::load().label(id, &vaults)
            )
        },
    );
    confirm_permanent(
        yes,
        &format!("Permanently delete {label} and every item in it?"),
        console,
    );
    ServerCommand::Delete(Target::Vault {
        key: if let Some(k) = key {
            resolved_key(k, console)
        } else {
            PasswordType::Password(hidden(
                console,
                "Master password of the vault to delete: ",
                "master password",
            ))
        },
        keep_key,
        vault_file,
    })
}

fn confirm_permanent(yes: bool, prompt: &str, console: &Output) {
    use std::io::{self, Write};
    if yes {
        return;
    }
    if !console.can_prompt() || password_manager::prompt::from_stdin() {
        console.exit_error(
            "Permanent deletion requires confirmation. Rerun with --yes to confirm.",
            2,
        );
    }
    eprint!("{prompt} This cannot be undone. Type yes to continue: ");
    let _ = io::stderr().flush();
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() || answer.trim() != "yes" {
        console.exit_error("Deletion canceled; nothing was deleted.", 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use password_manager::cli::Cli;

    #[test]
    fn generated_update_becomes_a_domain_secret_before_transport() {
        let cli = Cli::try_parse_from([
            "pm",
            "update",
            "--id",
            "3",
            "--name",
            "Renamed",
            "--password",
            "--generate-password",
        ])
        .unwrap();
        let conf = config::Config::default();
        let command = prepare_command(cli.command.unwrap(), &conf, &Output::default());
        let ServerCommand::Update(update) = &command else {
            panic!("expected typed update");
        };
        assert_eq!(update.entry.update.name.as_deref(), Some("Renamed"));
        let secret = update.entry.password.as_deref().unwrap();
        assert_eq!(secret.len(), conf.genpass.length as usize);
        assert!(!format!("{command:?}").contains(secret));
        let wire = serde_json::to_value(&update.entry).unwrap();
        assert_eq!(wire["password"].as_str(), Some(secret.as_str()));
        assert!(wire["update"].get("generate_password").is_none());
    }

    #[test]
    fn field_copy_preserves_the_configured_timeout() {
        let cli = Cli::try_parse_from(["pm", "get", "--id", "3", "--field", "recovery", "--copy"])
            .unwrap();
        let mut conf = config::Config::default();
        conf.clipboard.timeout = 42;
        assert!(matches!(
            prepare_command(cli.command.unwrap(), &conf, &Output::default()),
            ServerCommand::GetField {
                target: Target::Id(3),
                copy_timeout: Some(42),
                ..
            }
        ));
    }
}
