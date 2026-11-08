use super::output::Output;
use password_manager::{
    cli::SyncCommands,
    client::AuthenticatedClient,
    cloud::{self, Action},
    config::Config,
    protocol::ResponsePayload,
    server::start,
    types::ServerCommand,
};
use std::{
    io::{self, Write},
    path::Path,
};

pub(super) async fn run(
    command: SyncCommands,
    conf: &Config,
    path: &Path,
    client: &AuthenticatedClient,
    running: bool,
    console: &Output,
) {
    match command {
        SyncCommands::Connect { url, token_file } => {
            cloud::validate_server_url(&url).unwrap_or_else(|e| console.exit_error(&e, 2));
            let token = match token_file {
                Some(path) => {
                    cloud::read_token_file(&path).unwrap_or_else(|e| console.exit_error(&e, 1))
                }
                None => zeroize::Zeroizing::new(
                    rpassword::prompt_password("Device token: ")
                        .unwrap_or_else(|e| console.exit_error(&e.to_string(), 1)),
                ),
            };
            let config = conf.clone();
            let path = path.to_owned();
            let result = tokio::task::spawn_blocking(move || {
                cloud::connect_with_token(config, &url, &token, &path)
            })
            .await;
            match result {
                Ok(Ok(_)) => console.print_success("Connected to encrypted vault sync server"),
                Ok(Err(e)) => console.exit_error(&format!("Connection failed: {e}"), 1),
                Err(e) => console.exit_error(&e.to_string(), 1),
            }
        }
        command => {
            if !running {
                start(client.port).unwrap_or_else(|e| console.exit_error(&e, 1));
            }
            let action = match command {
                SyncCommands::Vaults => Action::List,
                SyncCommands::Pull { id, copy } => {
                    let id = id.unwrap_or_else(|| choose_vault(client, console));
                    if copy {
                        Action::PullCopy(id)
                    } else {
                        Action::Pull(id)
                    }
                }
                SyncCommands::Enable => Action::Enable,
                SyncCommands::Disable => Action::Disable,
                SyncCommands::Status => Action::Status,
                SyncCommands::Check => Action::Check,
                SyncCommands::Now => Action::Now,
                _ => unreachable!("connect handled above"),
            };
            if let Err(code) = console.send_command(client, ServerCommand::Cloud(action)) {
                std::process::exit(code);
            }
        }
    }
}
fn choose_vault(client: &AuthenticatedClient, console: &Output) -> String {
    let response = client
        .request_response(ServerCommand::Cloud(Action::List))
        .unwrap_or_else(|e| console.exit_error(&e, 1));
    if response.code != 0 {
        console.exit_error(&response.error_message(), 1);
    }
    let ResponsePayload::Message(message) = response.payload else {
        console.exit_error("Invalid cloud vault list", 1)
    };
    let vaults: Vec<cloud::RemoteVault> =
        serde_json::from_str(&message).unwrap_or_else(|e| console.exit_error(&e.to_string(), 1));
    if vaults.len() == 1 {
        return vaults[0].id.clone();
    }
    if vaults.is_empty() {
        console.exit_error(
            "No cloud vaults are available. Enable sync for a vault on your other device first.",
            1,
        );
    }
    if !console.can_prompt() {
        console.exit_error(
            "Multiple cloud vaults are available; supply an ID from pm sync vaults",
            2,
        );
    }
    for (index, vault) in vaults.iter().enumerate() {
        eprintln!("{}: {} ({} bytes)", index + 1, vault.id, vault.size);
    }
    eprint!("Choose a cloud vault [1-{}]: ", vaults.len());
    let _ = io::stderr().flush();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap_or_else(|e| console.exit_error(&e.to_string(), 1));
    input
        .trim()
        .parse::<usize>()
        .ok()
        .and_then(|i| i.checked_sub(1))
        .and_then(|i| vaults.get(i))
        .map(|v| v.id.clone())
        .unwrap_or_else(|| console.exit_error("Invalid vault selection", 2))
}
