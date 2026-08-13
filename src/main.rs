mod cli;
mod client;
mod clpboard;
mod config;
mod encryption;
mod file;
mod password;
mod server;
mod types;
mod vault;
use crate::{
    cli::{Cli, CliCommands, DeleteArgs, cli_parse},
    client::manager,
    config::{read_config, update},
    encryption::create_password,
    password::{gen_pass, pass_gen, pass_str},
    server::{is_running, server, start},
    types::{
        DeleteType, ImportArgs, PasswordEntry, PasswordType, ServerCommands, UnlockInfo,
        UpdateStruct,
    },
};
use clap::CommandFactory;
use clap_complete::generate;
use directories::ProjectDirs;
use std::{fs, io};

fn which_type(which: DeleteArgs) -> DeleteType {
    if let Some(id) = which.id {
        DeleteType::Id(id)
    } else if let Some(name) = which.entry_name {
        DeleteType::Name(name)
    } else {
        panic!("must provide --id or --entry-name")
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
    if let Some(command) = cli.command {
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
            ) => gen_pass(
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
                copy_time.unwrap_or(conf.clpboard.clp_timeout),
            ),
            (CliCommands::Passcheck { password }, _) => pass_str(&password),
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
                manager(ServerCommands::Lock(true));
            }
            (CliCommands::Unlock { key, timeout }, true) => {
                manager(ServerCommands::UnLock(UnlockInfo {
                    key: if let Some(k) = key {
                        PasswordType::Key(k)
                    } else {
                        PasswordType::Password(
                            rpassword::prompt_password("Enter master password: ").unwrap(),
                        )
                    },
                    timeout: timeout.timeout.unwrap_or(conf.unlock.unlock_timeout),
                }));
            }
            (CliCommands::Status, true) => {
                manager(ServerCommands::Status);
            }
            (CliCommands::Kill, true) => {
                manager(ServerCommands::Kill);
            }
            (CliCommands::Start, false) => start(),
            (CliCommands::Start, true) => start(),
            (CliCommands::Run, false) => server().await,
            (CliCommands::Run, true) => println!("Server is already running."),
            (CliCommands::New { key_path }, true) => {
                manager(ServerCommands::New(if let Some(kp) = key_path {
                    PasswordType::Key(kp)
                } else {
                    PasswordType::Password(create_password())
                }));
            }
            (
                CliCommands::Add {
                    name,
                    username,
                    url,
                    notes,
                    gen_password,
                    copy,
                    no_copy,
                },
                true,
            ) => {
                manager(ServerCommands::Add(PasswordEntry {
                    name,
                    username,
                    password: if !gen_password {
                        create_password()
                    } else {
                        pass_gen(conf.genpass.length)
                    },
                    url,
                    notes,
                    which: None,
                    copy: if !copy && !no_copy {
                        conf.copy.copy_pass
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
                    manager(ServerCommands::Delete(DeleteType::Id(i)));
                }
                (None, Some(n), _) => {
                    manager(ServerCommands::Delete(DeleteType::Name(n)));
                }
                (None, None, true) => {
                    manager(ServerCommands::Delete(DeleteType::Vault(
                        if let Some(k) = key {
                            PasswordType::Key(k)
                        } else {
                            PasswordType::Password(create_password())
                        },
                    )));
                }
                _ => panic!("not good"),
            },
            (CliCommands::View, true) => {
                manager(ServerCommands::View);
            }
            (CliCommands::Update { add, which }, true) => {
                manager(ServerCommands::Update(UpdateStruct {
                    which: which_type(which),
                    password: if add.password {
                        if !add.gen_password {
                            Some(create_password())
                        } else {
                            Some(pass_gen(conf.genpass.length))
                        }
                    } else {
                        None
                    },
                    update: add,
                }));
            }
            (CliCommands::Get { which }, true) => {
                manager(ServerCommands::Get(which_type(which)));
            }
            (CliCommands::Export { path }, true) => {
                manager(ServerCommands::Export(path));
            }
            (
                CliCommands::Import {
                    path,
                    new,
                    key_path,
                },
                true,
            ) => {
                let keypass = if key_path.is_some() {
                    PasswordType::Key(key_path.clone().unwrap())
                } else {
                    PasswordType::Password(create_password())
                };
                manager(ServerCommands::Import(ImportArgs {
                    path,
                    new,
                    key_pass: keypass,
                }));
            }
            (_, false) => println!("Server is not running. Start it with `pm start`."),
        };
    }
}
