use password_manager::{cli::CliCommands, client, config, server::is_running};

pub(crate) mod output;
use output::Output;
mod duo;
mod local;
mod remote;
mod session;
mod sync;
mod totp;
mod vaults;

pub async fn run(
    command: CliCommands,
    conf: config::Config,
    config_file: std::path::PathBuf,
    client: client::AuthenticatedClient,
    console: Output,
) {
    let port = client.port;
    // Each probe is a full authenticated round trip; run it only when needed.
    let running = std::cell::OnceCell::new();
    let server_running = || *running.get_or_init(|| is_running(port));
    let configured = std::cell::OnceCell::new();
    let configured_server_running = || {
        *configured.get_or_init(|| {
            if port == conf.server.port {
                server_running()
            } else {
                is_running(conf.server.port)
            }
        })
    };
    if let Some(command) = local::run(
        command,
        &conf,
        &config_file,
        &client,
        &server_running,
        &configured_server_running,
        &console,
    )
    .await
    {
        if !server_running() {
            // Creating or opening a vault needs the server, so start it
            // instead of making the user run `pm start` first.
            if matches!(
                command,
                CliCommands::New { .. } | CliCommands::Unlock { .. }
            ) {
                if let Err(error) = password_manager::server::start(port) {
                    let hint = if matches!(
                        error,
                        password_manager::server::StartError::PortInUse(_)
                    ) {
                        format!(
                            " Another program uses port {port}. Choose a free one with `pm config \
                             --server-port PORT`, or use `--port PORT` for this command."
                        )
                    } else {
                        String::new()
                    };
                    let error = error.to_string();
                    let error = error.trim_end_matches('.');
                    console.exit_error(&format!("Could not start the server: {error}.{hint}"), 1);
                }
                // `pm new` reports the created vault itself; unlocking says the server started.
                if matches!(command, CliCommands::Unlock { .. }) {
                    console.print_note("Started the background server.");
                }
            } else {
                let none_yet = password_manager::vault::list_vaults()
                    .map(|vaults| vaults.is_empty())
                    .unwrap_or(false);
                console.exit_error(
                    if none_yet {
                        "No vault yet. Create one with `pm new --name NAME` (it starts the \
                         background server for you)."
                    } else {
                        "Server is not running, so no vault is open. Run `pm unlock` to start \
                         it and open your vault."
                    },
                    1,
                );
            }
        }
        remote::run(command, &conf, &client, &console).await;
    }
}
