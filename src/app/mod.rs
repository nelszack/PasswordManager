use password_manager::{cli::CliCommands, client, config, server::is_running};

mod local;
mod remote;

pub async fn run(
    command: CliCommands,
    conf: config::Config,
    config_file: std::path::PathBuf,
    client: client::AuthenticatedClient,
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
    )
    .await
    {
        if !server_running {
            client::exit_error("Server is not running. Start it with `pm start`.", 1);
        }
        remote::run(command, &conf, &client);
    }
}
