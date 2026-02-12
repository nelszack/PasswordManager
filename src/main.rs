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
    clpboard::cpy,
    config::{read_config, update},
    encryption::create_password,
    password::{gen_pass, pass_str},
    server::{server, start},
    types::{
        DeleteType, ImportArgs, PasswordEntry, PasswordType, ServerCommands, UnlockInfo,
        UpdateStruct,
    },
    vault::create_vault,
};

fn main() {
    let cli = cli_parse();
    let conf = read_config();
    if let Some(command) = cli.command {
        match command {
            CliCommands::Genpass {
                length,
                no_stats,
                stats,
            } => gen_pass(
                length.unwrap_or(conf.genpass.length),
                if !stats && !no_stats {
                    conf.genpass.stats
                } else {
                    if stats { true } else { false }
                },
            ),
            CliCommands::Passcheck { password } => pass_str(&password),
            CliCommands::Clpb { timeout } => {
                cpy("testpass", timeout.timeout.unwrap_or(conf.clpboard.timeout))
            }
            CliCommands::Config(command) => update(command),
            CliCommands::Lock => manager(ServerCommands::Lock(true)),
            CliCommands::Unlock { key, timeout } => manager(ServerCommands::UnLock(UnlockInfo {
                key: if key.is_some() {
                    PasswordType::Key(key.unwrap())
                } else {
                    PasswordType::Password(Some(
                        rpassword::prompt_password("enter password: ").unwrap(),
                    ))
                },
                timeout: timeout.timeout,
            })),
            CliCommands::Status => manager(ServerCommands::Status),
            CliCommands::Kill => manager(ServerCommands::Kill),
            CliCommands::Start => start(),
            CliCommands::Run { key } => server(key.unwrap_or("none".into())),
            CliCommands::New { key_path } => {
                let mut keypass = if key_path.is_some() {
                    PasswordType::Key(key_path.unwrap())
                } else {
                    PasswordType::Password(None)
                };
                create_vault(&mut keypass);
            }
            CliCommands::Add {
                name,
                username,
                url,
                notes,
            } => manager(ServerCommands::Add(PasswordEntry {
                name: name,
                username: username,
                password: create_password(),
                url: url,
                notes: notes,
                which: None,
            })),
            CliCommands::Delete(DeleteArgs { id, entry_name }) => match (id, entry_name) {
                (Some(i), None) => manager(ServerCommands::Delete(DeleteType::Id(i))),
                (None, Some(n)) => manager(ServerCommands::Delete(DeleteType::Name(n))),
                _ => panic!("not good"),
            },
            CliCommands::View => manager(ServerCommands::View),
            CliCommands::Update { add, which } => manager(ServerCommands::Update(UpdateStruct {
                which: if which.id.is_some() {
                    DeleteType::Id(which.id.unwrap())
                } else {
                    DeleteType::Name(which.entry_name.unwrap())
                },
                update: add,
            })),
            CliCommands::Get { which } => manager(ServerCommands::Get(if which.id.is_some() {
                DeleteType::Id(which.id.unwrap())
            } else {
                DeleteType::Name(which.entry_name.unwrap())
            })),
            CliCommands::Export { path } => {
                manager(ServerCommands::Export(path));
            }
            CliCommands::Import {
                path,
                new,
                key_path,
            } => {
                if new {
                    let mut keypass = if key_path.is_some() {
                        PasswordType::Key(key_path.clone().unwrap())
                    } else {
                        PasswordType::Password(None)
                    };
                    create_vault(&mut keypass);
                }
                manager(ServerCommands::Import(ImportArgs {
                    path: path,
                    new: new,
                    key_path: key_path,
                }))
            }
        };
    }
}
