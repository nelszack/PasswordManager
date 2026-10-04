use clap::CommandFactory;
use password_manager::{
    cli::{Cli, CliCommands, cli_parse},
    client, clipboard,
    config::try_read_config,
    file::{config_dir, data_dir},
    native_messaging,
};
use std::fs;
mod app;

#[tokio::main]
async fn main() {
    let invoked_as_native_host = native_messaging::invoked_directly();
    let cli = (!invoked_as_native_host).then(cli_parse);
    if let Some(CliCommands::ClipboardHelper { timeout }) =
        cli.as_ref().and_then(|cli| cli.command.as_ref())
    {
        if let Err(error) = clipboard::run_helper(*timeout) {
            eprintln!("Clipboard helper failed: {error}");
            std::process::exit(1);
        }
        return;
    }
    let config_path = config_dir();
    let data_path = data_dir();
    if let Err(error) =
        fs::create_dir_all(&config_path).and_then(|_| fs::create_dir_all(&data_path))
    {
        eprintln!("Error: could not create application directories: {error}");
        std::process::exit(1);
    }
    let config_file = config_path.join("config.toml");
    if invoked_as_native_host {
        let conf = match try_read_config(&config_file) {
            Ok(config) => config,
            Err(error) => {
                eprintln!("Native messaging host error: {error}");
                std::process::exit(1);
            }
        };
        let client = client::AuthenticatedClient::new(conf.server.port);
        if let Err(error) = native_messaging::run(&client) {
            eprintln!("Native messaging host error: {error}");
            std::process::exit(1);
        }
        return;
    }
    let cli = cli.expect("native host returned before CLI dispatch");
    client::configure_output(cli.json, cli.quiet);
    let conf = match try_read_config(&config_file) {
        Ok(config) => config,
        Err(error) => client::exit_error(&error, 1),
    };
    let port = cli.port.unwrap_or(conf.server.port);
    let client = client::AuthenticatedClient::new(port);
    let Some(command) = cli.command else {
        let _ = Cli::command().print_help();
        println!();
        return;
    };
    app::run(command, conf, config_file, client).await;
}
