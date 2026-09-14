mod cli;
mod client;
mod clipboard;
mod config;
mod encryption;
mod file;
mod native_messaging;
mod password;
mod protocol;
mod server;
mod types;
mod vault;
use crate::{
    cli::{
        BackupCommands, Cli, CliCommands, DeleteArgs, EntryArgs, NativeHostCommands, TotpCommands,
        cli_parse,
    },
    client::send_command,
    config::{try_read_config, try_update},
    encryption::prompt_for_password,
    password::{
        PasswordOptions, generate_passphrase, generate_password as make_password,
        generate_password_with_options, print_generated_password, print_password_strength,
    },
    server::{is_running, server, start},
    types::{
        AuditOptions, BackupRequest, CustomField, EntryUpdate, ImportRequest, PasswordEntry,
        PasswordType, SearchFilter, ServerCommand, Target, TotpCommand, UnlockInfo,
    },
};
use clap::CommandFactory;
use clap_complete::generate;
use directories::ProjectDirs;
use std::{fs, io};

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

struct SilentPipe(io::Stdout);

impl io::Write for SilentPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.0.write(buf) {
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(buf.len()),
            r => r,
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[tokio::main]
async fn main() {
    if native_messaging::invoked_directly() {
        if let Err(error) = native_messaging::run() {
            eprintln!("Native messaging host error: {error}");
        }
        return;
    }
    let Some(proj_dir) = ProjectDirs::from("com", "myproject", "password_manager") else {
        eprintln!("Error: could not locate the application data directory.");
        return;
    };
    let config_path = proj_dir.config_dir();
    let data_path = proj_dir.data_dir();
    if let Err(error) = fs::create_dir_all(config_path).and_then(|_| fs::create_dir_all(data_path))
    {
        eprintln!("Error: could not create application directories: {error}");
        return;
    }
    let config_file = config_path.join("config.toml");
    let cli = cli_parse();
    client::configure_output(cli.json, cli.quiet);
    let conf = match try_read_config(&config_file) {
        Ok(config) => config,
        Err(error) => client::exit_error(&error, 1),
    };
    let server_running = is_running();
    let Some(command) = cli.command else {
        let _ = Cli::command().print_help();
        println!();
        return;
    };
    match (command, server_running) {
        (
            CliCommands::Genpass {
                length,
                no_stats,
                stats,
                copy,
                no_copy,
                copy_time,
                no_uppercase,
                no_lowercase,
                no_digits,
                no_symbols,
                symbols,
                exclude_ambiguous,
                passphrase,
                words,
                separator,
            },
            _,
        ) => {
            let show_stats = if !stats && !no_stats {
                conf.genpass.stats
            } else {
                stats
            };
            let should_copy = if !copy && !no_copy {
                conf.genpass.copy
            } else {
                copy
            };
            let generated = if passphrase {
                generate_passphrase(words, &separator)
            } else {
                let symbol_set = if no_symbols {
                    None
                } else {
                    Some(symbols.as_deref().unwrap_or("!@#$%^&*-_=+"))
                };
                generate_password_with_options(
                    length.unwrap_or(conf.genpass.length),
                    &PasswordOptions {
                        uppercase: !no_uppercase,
                        lowercase: !no_lowercase,
                        digits: !no_digits,
                        symbols: symbol_set,
                        exclude_ambiguous,
                    },
                )
            };
            match generated {
                Ok(password) => print_generated_password(
                    password,
                    show_stats,
                    should_copy,
                    copy_time.unwrap_or(conf.clipboard.timeout),
                ),
                Err(error) => eprintln!("Error: {error}"),
            }
        }
        (CliCommands::Passcheck { password }, _) => print_password_strength(&password),
        (CliCommands::Completions { shell, output }, _) => {
            let mut cmd = Cli::command();
            if output.to_string_lossy() == "-" {
                generate(shell, &mut cmd, "pm", &mut SilentPipe(io::stdout()));
            } else {
                let mut file = match fs::File::create(&output) {
                    Ok(file) => file,
                    Err(error) => client::exit_error(
                        &format!("could not create {}: {error}", output.display()),
                        1,
                    ),
                };
                generate(shell, &mut cmd, "pm", &mut file);
                println!("Completions written to {}", output.display());
            }
        }
        (CliCommands::NativeHost { command }, _) => match command {
            NativeHostCommands::Install {
                extension_id,
                browser,
            } => match native_messaging::install(&extension_id, browser) {
                Ok(path) => println!("Native messaging host installed at {}", path.display()),
                Err(error) => eprintln!("Error: {error}"),
            },
            NativeHostCommands::Run => {
                if let Err(error) = native_messaging::run() {
                    eprintln!("Native messaging host error: {error}");
                }
            }
        },
        (CliCommands::Config(command), _) => {
            if let Err(error) = try_update(conf, command, &config_file) {
                client::exit_error(&error, 1);
            }
        }
        (CliCommands::Lock, true) => {
            send_command(ServerCommand::Lock(true));
        }
        (CliCommands::Unlock { key, timeout }, true) => {
            send_command(ServerCommand::Unlock(UnlockInfo {
                key: if let Some(k) = key {
                    PasswordType::Key(k)
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
            }));
        }
        (CliCommands::Status, true) => {
            send_command(ServerCommand::Status);
        }
        (CliCommands::Kill, true) => {
            send_command(ServerCommand::Kill);
        }
        (CliCommands::Start, false) | (CliCommands::Start, true) => {
            if let Err(error) = start() {
                client::exit_error(&error, 1);
            }
        }
        (CliCommands::Run, false) => {
            if let Err(error) = server(
                conf.recovery.password_history_limit,
                conf.recovery.trash_retention_days,
            )
            .await
            {
                client::exit_error(&error, 1);
            }
        }
        (CliCommands::Run, true) => println!("Server is already running."),
        (CliCommands::New { key_path }, true) => {
            send_command(ServerCommand::New(if let Some(kp) = key_path {
                PasswordType::Key(kp)
            } else {
                PasswordType::Password(prompt_for_password())
            }));
        }
        (CliCommands::Rekey { key_path }, true) => {
            send_command(ServerCommand::Rekey(if let Some(kp) = key_path {
                PasswordType::Key(kp)
            } else {
                PasswordType::Password(prompt_for_password())
            }));
        }
        (
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
            },
            true,
        ) => {
            let custom_fields = match custom_fields(fields, secret_fields) {
                Ok(fields) => fields,
                Err(error) => {
                    client::exit_error(&error, 2);
                }
            };
            let mut urls = url.into_iter();
            let primary_url = urls.next();
            let password = if matches!(kind, crate::types::ItemKind::Identity) {
                String::new()
            } else if !generate_password {
                prompt_for_password()
            } else {
                make_password(conf.genpass.length)
            };
            send_command(ServerCommand::AddTyped(crate::types::TypedEntry {
                entry: PasswordEntry {
                    name,
                    username,
                    password,
                    url: primary_url,
                    notes,
                    copy: if !copy && !no_copy {
                        kind == crate::types::ItemKind::Login && conf.copy.passwords
                    } else {
                        copy
                    },
                },
                kind,
                additional_urls: urls.collect(),
                custom_fields,
            }));
        }
        (
            CliCommands::Delete(DeleteArgs {
                id,
                entry_name,
                vault,
                key,
            }),
            true,
        ) => match (id, entry_name, vault) {
            (Some(i), None, _) => {
                send_command(ServerCommand::Delete(Target::Id(i)));
            }
            (None, Some(n), _) => {
                send_command(ServerCommand::Delete(Target::Name(n)));
            }
            (None, None, true) => {
                send_command(ServerCommand::Delete(Target::Vault(if let Some(k) = key {
                    PasswordType::Key(k)
                } else {
                    PasswordType::Password(prompt_for_password())
                })));
            }
            _ => unreachable!("clap requires exactly one delete target"),
        },
        (CliCommands::View(options), true) => {
            send_command(ServerCommand::View(options.into()));
        }
        (CliCommands::Search(args), true) => {
            send_command(ServerCommand::Search(SearchFilter {
                query: args.query,
                name: args.name,
                username: args.username,
                url: args.url,
                notes: args.notes,
                list: args.list.into(),
            }));
        }
        (CliCommands::History { target }, true) => {
            send_command(ServerCommand::History(target_type(target)));
        }
        (CliCommands::RestorePassword { target, revision }, true) => {
            send_command(ServerCommand::RestorePassword {
                target: target_type(target),
                revision,
            });
        }
        (CliCommands::Trash, true) => {
            send_command(ServerCommand::Trash);
        }
        (CliCommands::Restore { id }, true) => {
            send_command(ServerCommand::RestoreTrash(id));
        }
        (CliCommands::Purge(args), true) => {
            send_command(ServerCommand::PurgeTrash(args.id));
        }
        (
            CliCommands::Audit {
                stale_days,
                breaches,
                require_totp,
            },
            true,
        ) => {
            send_command(ServerCommand::Audit(AuditOptions {
                stale_days,
                check_breaches: breaches,
                require_totp,
            }));
        }
        (CliCommands::Totp { command }, true) => match command {
            TotpCommands::Set { target } => {
                match rpassword::prompt_password("TOTP Base32 secret or otpauth URI: ") {
                    Ok(configuration) => send_command(ServerCommand::Totp(TotpCommand::Set {
                        target: target_type(target),
                        configuration,
                    })),
                    Err(error) => eprintln!("Could not read TOTP configuration: {error}"),
                }
            }
            TotpCommands::Show {
                target,
                copy,
                copy_time,
            } => send_command(ServerCommand::Totp(TotpCommand::Show {
                target: target_type(target),
                copy_timeout: copy.then_some(copy_time.unwrap_or(conf.clipboard.timeout)),
            })),
            TotpCommands::Remove { target } => {
                send_command(ServerCommand::Totp(TotpCommand::Remove {
                    target: target_type(target),
                }));
            }
        },
        (CliCommands::Backup { command }, true) => match command {
            BackupCommands::Create {
                path,
                key_path,
                force,
            } => send_command(ServerCommand::Backup(BackupRequest {
                path,
                key_pass: key_path.map_or_else(
                    || PasswordType::Password(prompt_for_password()),
                    PasswordType::Key,
                ),
                force,
            })),
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
                    PasswordType::Key,
                );
                send_command(ServerCommand::RestoreBackup(BackupRequest {
                    path,
                    key_pass,
                    force,
                }));
            }
        },
        (
            CliCommands::Update {
                add,
                target,
                metadata,
            },
            true,
        ) => {
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
            send_command(ServerCommand::UpdateTyped(crate::types::TypedUpdate {
                entry: EntryUpdate {
                    target: target_type(target),
                    password,
                    update: add,
                },
                kind: metadata.kind,
                add_url: metadata.add_url,
                remove_url: metadata.remove_url,
                clear_urls: metadata.clear_urls,
                set_fields,
                remove_fields: metadata.remove_fields,
                clear_fields: metadata.clear_fields,
            }));
        }
        (
            CliCommands::Get {
                target,
                password_only,
            },
            true,
        ) => {
            send_command(if password_only {
                ServerCommand::GetSecret(target_type(target))
            } else {
                ServerCommand::Get(target_type(target))
            });
        }
        (CliCommands::Export { path }, true) => {
            send_command(ServerCommand::Export(path));
        }
        (
            CliCommands::Import {
                path,
                new,
                key_path,
                preview,
                conflicts,
            },
            true,
        ) => {
            let keypass = if preview && new {
                PasswordType::Password(String::new())
            } else {
                match key_path {
                    Some(path) => PasswordType::Key(path),
                    None => PasswordType::Password(prompt_for_password()),
                }
            };
            send_command(ServerCommand::Import(ImportRequest {
                path,
                new,
                key_pass: keypass,
                preview,
                conflicts,
                password_history_limit: conf.recovery.password_history_limit,
            }));
        }
        (_, false) => client::exit_error("Server is not running. Start it with `pm start`.", 1),
    };
}
