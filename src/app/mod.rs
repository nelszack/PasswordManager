use password_manager::{cli::CliCommands, client, config, server::is_running};

pub(crate) mod output;
use output::Output;
mod duo;
mod local;
mod remote;
mod session;
mod sync;
mod totp;

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
            console.exit_error("Server is not running. Start it with `pm start`.", 1);
        }
        remote::run(command, &conf, &client, &console).await;
    }
}
