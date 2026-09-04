mod cli;
mod client;
mod clipboard;
mod config;
mod encryption;
mod file;
mod password;
mod server;
mod types;
mod vault;
use crate::{
    cli::{Cli, CliCommands, DeleteArgs, EntryArgs, cli_parse},
    client::send_command,
    config::{read_config, update},
    encryption::prompt_for_password,
    password::{
        generate_and_print_password, generate_password as make_password, print_password_strength,
    },
    server::{is_running, server, start},
    types::{
        EntryUpdate, ImportRequest, PasswordEntry, PasswordType, ServerCommand, Target, UnlockInfo,
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
    let proj_dir = ProjectDirs::from("com", "myproject", "password_manager").unwrap();
    let config_path = proj_dir.config_dir();
    let data_path = proj_dir.data_dir();
    fs::create_dir_all(config_path).unwrap();
    fs::create_dir_all(data_path).unwrap();
    let config_file = config_path.join("config.toml");
    let cli = cli_parse();
    let conf = read_config(&config_file);
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
            },
            _,
        ) => generate_and_print_password(
            length.unwrap_or(conf.genpass.length),
            if !stats && !no_stats {
                conf.genpass.stats
            } else {
                stats
            },
            if !copy && !no_copy {
                conf.genpass.copy
            } else {
                copy
            },
            copy_time.unwrap_or(conf.clipboard.timeout),
        ),
        (CliCommands::Passcheck { password }, _) => print_password_strength(&password),
        (CliCommands::Completions { shell, output }, _) => {
            let mut cmd = Cli::command();
            if output.to_string_lossy() == "-" {
                generate(shell, &mut cmd, "pm", &mut SilentPipe(io::stdout()));
            } else {
                let mut file = fs::File::create(&output).unwrap();
                generate(shell, &mut cmd, "pm", &mut file);
                println!("Completions written to {}", output.display());
            }
        }
        (CliCommands::Config(command), _) => update(conf, command, &config_file),
        (CliCommands::Lock, true) => {
            send_command(ServerCommand::Lock(true));
        }
        (CliCommands::Unlock { key, timeout }, true) => {
            send_command(ServerCommand::Unlock(UnlockInfo {
                key: if let Some(k) = key {
                    PasswordType::Key(k)
                } else {
                    PasswordType::Password(
                        rpassword::prompt_password("Enter master password: ").unwrap(),
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
        (CliCommands::Start, false) => start(),
        (CliCommands::Start, true) => start(),
        (CliCommands::Run, false) => server().await,
        (CliCommands::Run, true) => println!("Server is already running."),
        (CliCommands::New { key_path }, true) => {
            send_command(ServerCommand::New(if let Some(kp) = key_path {
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
                notes,
                generate_password,
                copy,
                no_copy,
            },
            true,
        ) => {
            send_command(ServerCommand::Add(PasswordEntry {
                name,
                username,
                password: if !generate_password {
                    prompt_for_password()
                } else {
                    make_password(conf.genpass.length)
                },
                url,
                notes,
                copy: if !copy && !no_copy {
                    conf.copy.passwords
                } else {
                    copy
                },
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
        (CliCommands::View, true) => {
            send_command(ServerCommand::View);
        }
        (CliCommands::Update { add, target }, true) => {
            send_command(ServerCommand::Update(EntryUpdate {
                target: target_type(target),
                password: if add.password {
                    if !add.generate_password {
                        Some(prompt_for_password())
                    } else {
                        Some(make_password(conf.genpass.length))
                    }
                } else {
                    None
                },
                update: add,
            }));
        }
        (CliCommands::Get { target }, true) => {
            send_command(ServerCommand::Get(target_type(target)));
        }
        (CliCommands::Export { path }, true) => {
            send_command(ServerCommand::Export(path));
        }
        (
            CliCommands::Import {
                path,
                new,
                key_path,
            },
            true,
        ) => {
            let keypass = match key_path {
                Some(path) => PasswordType::Key(path),
                None => PasswordType::Password(prompt_for_password()),
            };
            send_command(ServerCommand::Import(ImportRequest {
                path,
                new,
                key_pass: keypass,
            }));
        }
        (_, false) => println!("Server is not running. Start it with `pm start`."),
    };
}
