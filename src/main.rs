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
    cli::{CliCommands, DeleteArgs, cli_parse},
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
use directories::ProjectDirs;
use std::fs;

fn which_type(which: DeleteArgs) -> DeleteType {
    if let Some(id) = which.id {
        DeleteType::Id(id)
    } else if let Some(name) = which.entry_name {
        DeleteType::Name(name)
    } else {
        panic!("must provide --id or --entry-name")
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
                    if stats { true } else { false }
                },
                if !copy && !no_copy {
                    conf.genpass.copy
                } else {
                    if copy { true } else { false }
                },
                copy_time.unwrap_or(conf.clpboard.clp_timeout),
            ),
            (CliCommands::Passcheck { password }, _) => pass_str(&password),
            (CliCommands::Config(command), _) => update(conf, command, &config_file),
            (CliCommands::Lock, true) => {
                manager(ServerCommands::Lock(true));
            }
            (CliCommands::Unlock { key, timeout }, true) => {
                manager(ServerCommands::UnLock(UnlockInfo {
                    key: if key.is_some() {
                        PasswordType::Key(key.unwrap())
                    } else {
                        PasswordType::Password(
                            rpassword::prompt_password("enter password: ").unwrap(),
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
            (CliCommands::Run { key }, false) => server(key.unwrap_or("none".into())).await,
            (CliCommands::Run { .. }, true) => println!("server already running"),
            (CliCommands::New { key_path }, true) => {
                manager(ServerCommands::New(if key_path.is_some() {
                    PasswordType::Key(key_path.unwrap())
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
                        if copy { true } else { false }
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
                        if key.is_some() {
                            PasswordType::Key(key.unwrap())
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
                        if !add.gen_pass {
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
            (_, false) => println!("server not running"),
        };
    }
}
