use super::output::Output;
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
};
use std::fs;

/// `section.key = value` for every setting that differs between two configurations.
fn changed_settings(before: &config::Config, after: &config::Config) -> Vec<String> {
    let (Ok(toml::Value::Table(old)), Ok(toml::Value::Table(new))) =
        (toml::Value::try_from(before), toml::Value::try_from(after))
    else {
        return Vec::new();
    };
    let mut changed = Vec::new();
    for (section, values) in &new {
        let Some(values) = values.as_table() else {
            continue;
        };
        for (key, value) in values {
            let previous = old.get(section).and_then(|table| table.get(key));
            if previous != Some(value) {
                changed.push(format!("{section}.{key} = {value}"));
            }
        }
    }
    changed
}

pub(super) async fn run(
    command: CliCommands,
    conf: &config::Config,
    config_file: &std::path::Path,
    client: &client::AuthenticatedClient,
    server_running: &dyn Fn() -> bool,
    configured_server_running: &dyn Fn() -> bool,
    console: &Output,
) -> Option<CliCommands> {
    let port = client.port;
    // Probe the server only for commands whose behavior depends on it.
    match command {
        CliCommands::Sync { command } => {
            super::sync::run(
                command,
                conf,
                config_file,
                client,
                server_running(),
                console,
            )
            .await;
        }

        CliCommands::Vaults {
            command: None,
            rename,
            name,
        } => super::vaults::list_or_rename(conf, rename.as_deref(), name.as_deref(), console),
        CliCommands::GenerateCommandContract { check } => {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("extension");
            for (name, expected) in [
                (
                    "command_contract.js",
                    password_manager::protocol::native_contract::browser_contract(),
                ),
                (
                    "command_contract.d.ts",
                    password_manager::protocol::native_contract::browser_declarations(),
                ),
            ] {
                let path = root.join(name);
                if check {
                    if fs::read_to_string(&path).ok().as_deref() != Some(expected.as_str()) {
                        console.exit_error(
                            "Browser command contract is stale; run pm generate-command-contract",
                            1,
                        );
                    }
                } else if let Err(error) = fs::write(&path, expected) {
                    console.exit_error(
                        &format!("could not write browser command contract: {error}"),
                        1,
                    );
                }
            }
        }
        CliCommands::ClipboardHelper { timeout } => {
            if let Err(error) = clipboard::run_helper(timeout) {
                console.exit_error(&error, 1);
            }
        }
        CliCommands::GenerateCommandReference { check } => {
            if let Err(error) = docs::generate_command_reference(check) {
                console.exit_error(&error, 1);
            }
        }
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
        } => {
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
                    let password = zeroize::Zeroizing::new(password);
                    let (score, rating) = password_manager::password::strength_rating(&password);
                    let (output, warning) = generated_password_output(
                        password.to_string(),
                        show_stats,
                        should_copy,
                        copy_time.unwrap_or(conf.clipboard.timeout),
                    );
                    if console.is_json() {
                        // Typed data for scripts instead of display text.
                        console.print_data(
                            serde_json::json!({
                                "password": password.as_str(),
                                "score": score,
                                "rating": rating,
                                "copied": should_copy && warning.is_none(),
                                "copy_error": warning,
                            }),
                            "",
                        );
                    } else if console.stdout_is_terminal() || show_stats {
                        console.print_success(&output);
                    } else {
                        // In a pipe, print only the value (like `get --password-only`).
                        console.print_success(password.as_str());
                    }
                    if let Some(warning) = warning {
                        console.print_warning(&warning);
                    }
                }
                Err(error) => console.exit_error(&error, 2),
            }
        }
        CliCommands::Passcheck { password } => {
            let password = password.unwrap_or_else(|| {
                password_manager::prompt::hidden("Password to check: ", "password")
                    .unwrap_or_else(|error| console.exit_error(&error, 1))
            });
            let (score, rating) = password_manager::password::strength_rating(&password);
            console.print_data(
                serde_json::json!({"score": score, "rating": rating}),
                &password_strength_output(&password),
            );
        }
        CliCommands::Completions { shell, output } => {
            let mut cmd = Cli::command();
            if output.to_string_lossy() == "-" {
                let mut generated = Vec::new();
                generate(shell, &mut cmd, "pm", &mut generated);
                let generated = String::from_utf8(generated).unwrap_or_else(|error| {
                    console.exit_error(&format!("completion output was not UTF-8: {error}"), 1)
                });
                console.print_success(&generated);
            } else {
                let mut file = match fs::File::create(&output) {
                    Ok(file) => file,
                    Err(error) => console.exit_error(
                        &format!("could not create {}: {error}", output.display()),
                        1,
                    ),
                };
                generate(shell, &mut cmd, "pm", &mut file);
                console.print_success(&format!("Completions written to {}", output.display()));
            }
        }
        CliCommands::NativeHost { command } => match command {
            NativeHostCommands::Update => match native_messaging::update() {
                Ok(path) => console.print_success(&format!(
                    "Native messaging host updated at {}",
                    path.display()
                )),
                Err(error) => console.exit_error(&error, 1),
            },
            NativeHostCommands::Install {
                extension_id,
                browser,
            } => match native_messaging::install(extension_id.as_deref(), browser) {
                Ok(path) => console.print_success(&format!(
                    "Native messaging host installed at {}",
                    path.display()
                )),
                Err(error) => console.exit_error(&error, 1),
            },
            NativeHostCommands::Run => {
                if let Err(error) = native_messaging::run(client) {
                    console.exit_error(&format!("Native messaging host error: {error}"), 1);
                }
            }
        },
        CliCommands::Config(command) => {
            let requested_port = if command.reset {
                Some(password_manager::server::DEFAULT_PORT)
            } else {
                command.server_port
            };
            if requested_port.is_some_and(|new_port| new_port != conf.server.port)
                && configured_server_running()
            {
                console.exit_error(
                    "stop the running server before changing its configured port",
                    1,
                );
            }
            let restart_required = (command.reset
                || command.password_history_limit.is_some()
                || command.trash_retention_days.is_some()
                || command.ssh_agent.is_some())
                && configured_server_running();
            let effective = if command.has_updates() {
                try_update(conf.clone(), command, config_file)
                    .unwrap_or_else(|error| console.exit_error(&error, 1))
            } else {
                conf.clone()
            };
            let output = toml::to_string_pretty(&effective).unwrap_or_else(|error| {
                console.exit_error(&format!("could not display configuration: {error}"), 1)
            });
            console.print_data(
                serde_json::to_value(&effective).expect("config serializes"),
                &output,
            );
            // Confirm exactly what changed, after the full listing.
            let changed = changed_settings(conf, &effective);
            if !changed.is_empty() {
                console.print_note(&format!("Saved: {}.", changed.join(", ")));
            }
            if restart_required {
                console.print_warning(
                    "restart the server before the updated recovery or SSH agent settings take \
                     effect",
                );
            }
        }
        CliCommands::SshAgent { command: None } => {
            let path = password_manager::server::ssh_agent_socket();
            // PowerShell on Windows; POSIX shells elsewhere.
            #[cfg(windows)]
            let mut text = format!(
                "$env:SSH_AUTH_SOCK = '{}'",
                path.display().to_string().replace('\'', "''")
            );
            #[cfg(not(windows))]
            let mut text = format!(
                "SSH_AUTH_SOCK='{}'; export SSH_AUTH_SOCK;",
                path.display().to_string().replace('\'', r"'\''")
            );
            if !conf.server.ssh_agent {
                text.push_str(
                    "\n# The agent is off; enable it with `pm config --ssh-agent true` and \
                     restart the server.",
                );
            }
            console.print_data(
                serde_json::json!({
                    "socket": path,
                    "enabled": conf.server.ssh_agent,
                    "supported": cfg!(any(unix, windows)),
                }),
                &text,
            );
        }
        CliCommands::Start => match start(port) {
            Ok(message) => console.print_success(&message),
            Err(error) => console.exit_error(&error, 1),
        },
        CliCommands::Run if !server_running() => {
            if let Err(error) = server(
                port,
                conf.recovery.password_history_limit,
                conf.recovery.trash_retention_days,
                conf.server.ssh_agent,
            )
            .await
            {
                console.exit_error(&error, 1);
            }
        }
        CliCommands::Run => console.print_success("Server is already running."),
        command => return Some(command),
    };
    None
}
