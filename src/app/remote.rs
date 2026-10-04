use password_manager::{
    cli::{BackupCommands, CliCommands, DeleteArgs, EntryArgs, TotpCommands},
    client, config,
    encryption::{prompt_for_new_master_password, prompt_for_password},
    file::{resolve_key_path, resolve_new_key_path},
    password::generate_password as make_password,
    types::{
        self, AuditOptions, BackupRequest, CustomField, EntryUpdate, ImportRequest, PasswordEntry,
        PasswordType, SearchFilter, ServerCommand, Target, TotpCommand, UnlockInfo,
    },
    vault,
};

fn target_type(target: EntryArgs) -> Target {
    if let Some(id) = target.id {
        Target::Id(id)
    } else if let Some(name) = target.entry_name {
        Target::Name(name)
    } else {
        unreachable!("clap requires either --id or --entry-name")
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
            value: value.to_string(),
            secret: false,
        });
    }
    for name in secret_fields {
        let name = name.trim();
        if name.is_empty() {
            return Err("custom field names cannot be empty".to_string());
        }
        let value = rpassword::prompt_password(format!("{name}: "))
            .map_err(|error| format!("could not read custom field {name:?}: {error}"))?;
        parsed.retain(|existing| !existing.name.eq_ignore_ascii_case(name));
        parsed.push(CustomField {
            name: name.to_string(),
            value,
            secret: true,
        });
    }
    Ok(parsed)
}

fn resolved_new_key(path: String) -> PasswordType {
    PasswordType::Key(
        resolve_new_key_path(&path)
            .unwrap_or_else(|error| client::exit_error(&format!("invalid key path: {error}"), 2)),
    )
}

fn resolved_key(path: String) -> PasswordType {
    PasswordType::Key(
        resolve_key_path(&path)
            .unwrap_or_else(|error| client::exit_error(&format!("invalid key path: {error}"), 2)),
    )
}

pub(super) fn run(
    command: CliCommands,
    conf: &config::Config,
    client: &client::AuthenticatedClient,
) {
    client.send_command(prepare_command(command, conf));
}

fn prepare_command(command: CliCommands, conf: &config::Config) -> ServerCommand {
    match command {
        CliCommands::Lock => ServerCommand::Lock(true),

        CliCommands::Unlock {
            key,
            timeout,
            vault_file,
        } => {
            if let Some(name) = &vault_file
                && let Err(error) = vault::validate_vault_filename(name)
            {
                client::exit_error(&error.to_string(), 2);
            }
            ServerCommand::Unlock(UnlockInfo {
                vault_file,
                key: if let Some(k) = key {
                    resolved_key(k)
                } else {
                    PasswordType::Password(
                        rpassword::prompt_password("Enter master password: ").unwrap_or_else(
                            |error| {
                                client::exit_error(&format!("could not read password: {error}"), 1)
                            },
                        ),
                    )
                },
                timeout: timeout.timeout.unwrap_or(conf.unlock.timeout),
            })
        }
        CliCommands::Status => ServerCommand::Status,
        CliCommands::Kill => ServerCommand::Kill,
        CliCommands::New { key_path } => ServerCommand::New(if let Some(kp) = key_path {
            resolved_new_key(kp)
        } else {
            PasswordType::Password(prompt_for_new_master_password())
        }),
        CliCommands::Rekey { key_path } => ServerCommand::Rekey(if let Some(kp) = key_path {
            resolved_new_key(kp)
        } else {
            PasswordType::Password(prompt_for_new_master_password())
        }),

        CliCommands::Add {
            name,
            username,
            url,
            kind,
            notes,
            fields,
            secret_fields,
            generate_password,
            copy,
            no_copy,
        } => {
            if matches!(kind, types::ItemKind::Identity) && generate_password {
                client::exit_error("identity items do not have a primary secret to generate", 2);
            }
            let custom_fields = match custom_fields(fields, secret_fields) {
                Ok(fields) => fields,
                Err(error) => {
                    client::exit_error(&error, 2);
                }
            };
            let mut urls = url.into_iter();
            let primary_url = urls.next();
            let password = if matches!(kind, types::ItemKind::Identity) {
                String::new()
            } else if !generate_password {
                prompt_for_password()
            } else {
                make_password(conf.genpass.length)
            };
            ServerCommand::AddTypedWithOptions {
                entry: types::TypedEntry {
                    entry: PasswordEntry {
                        name,
                        username,
                        password,
                        url: primary_url,
                        notes,
                        copy: if !copy && !no_copy {
                            kind == types::ItemKind::Login && conf.copy.passwords
                        } else {
                            copy
                        },
                    },
                    kind,
                    additional_urls: urls.collect(),
                    custom_fields,
                },
                copy_timeout: conf.clipboard.timeout,
            }
        }

        CliCommands::Delete(DeleteArgs {
            id,
            entry_name,
            vault,
            key,
            keep_key,
        }) => match (id, entry_name, vault) {
            (Some(i), None, _) => ServerCommand::Delete(Target::Id(i)),
            (None, Some(n), _) => ServerCommand::Delete(Target::Name(n)),
            (None, None, true) => ServerCommand::Delete(Target::Vault {
                key: if let Some(k) = key {
                    resolved_key(k)
                } else {
                    PasswordType::Password(prompt_for_password())
                },
                keep_key,
            }),
            _ => unreachable!("clap requires exactly one delete target"),
        },
        CliCommands::View(options) => ServerCommand::View(options.into()),
        CliCommands::Search(args) => ServerCommand::Search(SearchFilter {
            query: args.query,
            name: args.name,
            username: args.username,
            url: args.url,
            notes: args.notes,
            list: args.list.into(),
        }),
        CliCommands::History { target } => ServerCommand::History(target_type(target)),
        CliCommands::RestorePassword { target, revision } => ServerCommand::RestorePassword {
            target: target_type(target),
            revision,
        },
        CliCommands::Trash => ServerCommand::Trash,
        CliCommands::Restore { id } => ServerCommand::RestoreTrash(id),
        CliCommands::Purge(args) => ServerCommand::PurgeTrash(args.id),

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
            TotpCommands::Set { target } => {
                match rpassword::prompt_password("TOTP Base32 secret or otpauth URI: ") {
                    Ok(configuration) => ServerCommand::Totp(TotpCommand::Set {
                        target: target_type(target),
                        configuration,
                    }),
                    Err(error) => client::exit_error(
                        &format!("could not read TOTP configuration: {error}"),
                        1,
                    ),
                }
            }
            TotpCommands::Show {
                target,
                copy,
                copy_time,
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
                path,
                key_pass: key_path.map_or_else(
                    || PasswordType::Password(prompt_for_new_master_password()),
                    resolved_key,
                ),
                force,
            }),
            BackupCommands::Restore {
                path,
                key_path,
                force,
            } => {
                let key_pass = key_path.map_or_else(
                    || {
                        PasswordType::Password(
                            rpassword::prompt_password("Backup password: ").unwrap_or_else(
                                |error| {
                                    client::exit_error(
                                        &format!("could not read backup password: {error}"),
                                        1,
                                    )
                                },
                            ),
                        )
                    },
                    resolved_key,
                );
                ServerCommand::RestoreBackup(BackupRequest {
                    path,
                    key_pass,
                    force,
                })
            }
        },

        CliCommands::Update {
            add,
            target,
            metadata,
        } => {
            let password = if add.password {
                if !add.generate_password {
                    Some(prompt_for_password())
                } else {
                    Some(make_password(conf.genpass.length))
                }
            } else {
                None
            };
            let set_fields = match custom_fields(metadata.fields, metadata.secret_fields) {
                Ok(fields) => fields,
                Err(error) => {
                    client::exit_error(&error, 2);
                }
            };
            ServerCommand::UpdateTyped(types::TypedUpdate {
                entry: EntryUpdate {
                    target: target_type(target),
                    password,
                    update: add.into(),
                },
                kind: metadata.kind,
                add_url: metadata.add_url,
                remove_url: metadata.remove_url,
                clear_urls: metadata.clear_urls,
                set_fields,
                remove_fields: metadata.remove_fields,
                clear_fields: metadata.clear_fields,
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
                ServerCommand::GetField {
                    target: target_type(target),
                    name,
                    copy_timeout: copy.then_some(conf.clipboard.timeout),
                }
            } else if password_only {
                ServerCommand::GetSecret(target_type(target))
            } else {
                ServerCommand::GetDetails {
                    target: target_type(target),
                    copy_timeout: conf.clipboard.timeout,
                    reveal_secrets,
                }
            }
        }
        CliCommands::Export { path, force } => ServerCommand::Export { path, force },

        CliCommands::Import {
            path,
            new,
            key_path,
            preview,
            conflicts,
        } => {
            if !new && key_path.is_some() {
                client::exit_error("--key can only be used together with --new", 2);
            }
            let keypass = if preview || !new {
                None
            } else {
                Some(match key_path {
                    Some(path) => resolved_new_key(path),
                    None => PasswordType::Password(prompt_for_new_master_password()),
                })
            };
            ServerCommand::Import(ImportRequest {
                path,
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
        let command = prepare_command(cli.command.unwrap(), &conf);
        let ServerCommand::UpdateTyped(update) = &command else {
            panic!("expected typed update");
        };
        assert_eq!(update.entry.update.name.as_deref(), Some("Renamed"));
        let secret = update.entry.password.as_deref().unwrap();
        assert_eq!(secret.len(), conf.genpass.length as usize);
        assert!(!format!("{command:?}").contains(secret));
        let wire = serde_json::to_value(&update.entry).unwrap();
        assert_eq!(wire["update"]["password"], true);
        assert_eq!(wire["update"]["generate_password"], false);
    }

    #[test]
    fn field_copy_preserves_the_configured_timeout() {
        let cli = Cli::try_parse_from(["pm", "get", "--id", "3", "--field", "recovery", "--copy"])
            .unwrap();
        let mut conf = config::Config::default();
        conf.clipboard.timeout = 42;
        assert!(matches!(
            prepare_command(cli.command.unwrap(), &conf),
            ServerCommand::GetField {
                target: Target::Id(3),
                copy_timeout: Some(42),
                ..
            }
        ));
    }
}
