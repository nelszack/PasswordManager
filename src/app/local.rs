use clap::CommandFactory;
use clap_complete::generate;
use password_manager::{
    cli::{Cli, CliCommands, NativeHostCommands},
    client, clipboard,
    config::{self, try_update},
    docs, native_messaging,
    password::{
        PasswordOptions, generate_passphrase, generate_password_with_options,
        generated_password_output, password_strength_output,
    },
    server::{server, start},
    vault,
};
use std::fs;

pub(super) async fn run(
    command: CliCommands,
    conf: &config::Config,
    config_file: &std::path::Path,
    client: &client::AuthenticatedClient,
    server_running: bool,
    configured_server_running: bool,
) -> Option<CliCommands> {
    let port = client.port;
    match (command, server_running) {
        (CliCommands::Vaults, _) => match vault::list_vaults() {
            Ok(names) => client::print_success(&names.join("\n")),
            Err(error) => client::exit_error(&error.to_string(), 1),
        },
        (CliCommands::ClipboardHelper { timeout }, _) => {
            if let Err(error) = clipboard::run_helper(timeout) {
                client::exit_error(&error, 1);
            }
        }
        (CliCommands::GenerateCommandReference { check }, _) => {
            if let Err(error) = docs::generate_command_reference(check) {
                client::exit_error(&error, 1);
            }
        }
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
                Ok(password) => {
                    let (output, warning) = generated_password_output(
                        password,
                        show_stats,
                        should_copy,
                        copy_time.unwrap_or(conf.clipboard.timeout),
                    );
                    client::print_success(&output);
                    if let Some(warning) = warning {
                        client::print_warning(&warning);
                    }
                }
                Err(error) => client::exit_error(&error, 2),
            }
        }
        (CliCommands::Passcheck { password }, _) => {
            let password = password.unwrap_or_else(|| {
                rpassword::prompt_password("Password to check: ").unwrap_or_else(|error| {
                    client::exit_error(&format!("could not read password: {error}"), 1)
                })
            });
            client::print_success(&password_strength_output(&password));
        }
        (CliCommands::Completions { shell, output }, _) => {
            let mut cmd = Cli::command();
            if output.to_string_lossy() == "-" {
                let mut generated = Vec::new();
                generate(shell, &mut cmd, "pm", &mut generated);
                let generated = String::from_utf8(generated).unwrap_or_else(|error| {
                    client::exit_error(&format!("completion output was not UTF-8: {error}"), 1)
                });
                client::print_success(&generated);
            } else {
                let mut file = match fs::File::create(&output) {
                    Ok(file) => file,
                    Err(error) => client::exit_error(
                        &format!("could not create {}: {error}", output.display()),
                        1,
                    ),
                };
                generate(shell, &mut cmd, "pm", &mut file);
                client::print_success(&format!("Completions written to {}", output.display()));
            }
        }
        (CliCommands::NativeHost { command }, _) => match command {
            NativeHostCommands::Update => match native_messaging::update() {
                Ok(path) => client::print_success(&format!(
                    "Native messaging host updated at {}",
                    path.display()
                )),
                Err(error) => client::exit_error(&error, 1),
            },
            NativeHostCommands::Install {
                extension_id,
                browser,
            } => match native_messaging::install(&extension_id, browser) {
                Ok(path) => client::print_success(&format!(
                    "Native messaging host installed at {}",
                    path.display()
                )),
                Err(error) => client::exit_error(&error, 1),
            },
            NativeHostCommands::Run => {
                if let Err(error) = native_messaging::run(client) {
                    client::exit_error(&format!("Native messaging host error: {error}"), 1);
                }
            }
        },
        (CliCommands::Config(command), _) => {
            let requested_port = if command.reset {
                Some(password_manager::server::DEFAULT_PORT)
            } else {
                command.server_port
            };
            if requested_port.is_some_and(|new_port| new_port != conf.server.port)
                && configured_server_running
            {
                client::exit_error(
                    "stop the running server before changing its configured port",
                    1,
                );
            }
            let restart_required = configured_server_running
                && (command.reset
                    || command.password_history_limit.is_some()
                    || command.trash_retention_days.is_some());
            let effective = if command.has_updates() {
                try_update(conf.clone(), command, config_file)
                    .unwrap_or_else(|error| client::exit_error(&error, 1))
            } else {
                conf.clone()
            };
            let output = toml::to_string_pretty(&effective).unwrap_or_else(|error| {
                client::exit_error(&format!("could not display configuration: {error}"), 1)
            });
            client::print_success(&output);
            if restart_required {
                client::print_warning(
                    "restart the server before the updated recovery settings take effect",
                );
            }
        }
        (CliCommands::Start, false) | (CliCommands::Start, true) => match start(port) {
            Ok(message) => client::print_success(&message),
            Err(error) => client::exit_error(&error, 1),
        },
        (CliCommands::Run, false) => {
            if let Err(error) = server(
                port,
                conf.recovery.password_history_limit,
                conf.recovery.trash_retention_days,
            )
            .await
            {
                client::exit_error(&error, 1);
            }
        }
        (CliCommands::Run, true) => client::print_success("Server is already running."),
        (command, _) => return Some(command),
    };
    None
}
