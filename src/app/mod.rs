use password_manager::{cli::CliCommands, client, config, server::is_running};

pub(crate) mod output;
use output::Output;
mod duo;
mod local;
mod remote;
mod session;
mod totp;

pub async fn run(
    command: CliCommands,
    conf: config::Config,
    config_file: std::path::PathBuf,
    client: client::AuthenticatedClient,
    console: Output,
) {
    let port = client.port;
    let server_running = is_running(port);
    let configured_server_running = if port == conf.server.port {
        server_running
    } else {
        is_running(conf.server.port)
    };
    if let Some(command) = local::run(
        command,
        &conf,
        &config_file,
        &client,
        server_running,
        configured_server_running,
        &console,
    )
    .await
    {
        if !server_running {
            console.exit_error("Server is not running. Start it with `pm start`.", 1);
        }
        remote::run(command, &conf, &client, &console).await;
    }
}
