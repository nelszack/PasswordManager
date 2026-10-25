use clap::CommandFactory;
use password_manager::{
    cli::{Cli, CliCommands, DuoCommands, cli_parse},
    client, clipboard,
    config::try_read_config,
    file::{config_dir, data_dir},
    native_messaging,
};
use std::fs;
mod app;
mod desktop;
#[cfg(feature = "desktop")]
mod gui;
use app::output::Output;

fn main() {
    let invoked_as_native_host = native_messaging::invoked_directly();
    if !invoked_as_native_host {
        // CompleteEnv modifies its activation environment. Run it while the
        // process is single-threaded, before Tokio or vault/config startup.
        clap_complete::CompleteEnv::with_factory(Cli::command).complete();
    }
    run(invoked_as_native_host);
}

fn output_error(cli: &Cli) -> Option<&'static str> {
    match &cli.command {
        Some(CliCommands::Duo {
            command: DuoCommands::Watch {
                interactive: true, ..
            },
        }) if cli.json || cli.quiet => Some(
            "Interactive Duo watch cannot use --json or --quiet; request details must be visible",
        ),
        Some(CliCommands::Duo {
            command: DuoCommands::Approve { .. } | DuoCommands::Deny { .. },
        }) if cli.quiet => Some(
            "Duo decisions cannot use --quiet; request details must be visible before confirmation",
        ),
        _ => None,
    }
}

fn run(invoked_as_native_host: bool) {
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
    let output = Output::new(cli.json, cli.quiet);
    if let Some(error) = output_error(&cli) {
        output.exit_error(error, 2);
    }
    if matches!(cli.command, None | Some(CliCommands::Gui { .. })) {
        if cli.json || cli.quiet {
            output.exit_error("The desktop interface does not support --json or --quiet. Choose a CLI command instead.", 2);
        }
        if matches!(
            cli.command,
            Some(CliCommands::Gui {
                install_shortcut: true
            })
        ) {
            match desktop::install_shortcut() {
                Ok(path) => {
                    output.print_success(&format!("Installed desktop launcher: {}", path.display()))
                }
                Err(error) => output.exit_error(&error, 1),
            }
            return;
        }
        #[cfg(not(feature = "desktop"))]
        output.exit_error("This build has no desktop interface. Rebuild with the desktop feature, or run pm --help for CLI commands.", 1);
        #[cfg(feature = "desktop")]
        {
            let conf =
                try_read_config(&config_file).unwrap_or_else(|error| output.exit_error(&error, 1));
            let port = cli.port.unwrap_or(conf.server.port);
            if let Err(error) = gui::run(conf, client::AuthenticatedClient::new(port)) {
                output.exit_error(&error, 1);
            }
            return;
        }
    }
    let conf = match try_read_config(&config_file) {
        Ok(config) => config,
        Err(error) => output.exit_error(&error, 1),
    };
    let port = cli.port.unwrap_or(conf.server.port);
    let client = client::AuthenticatedClient::new(port);
    let command = cli.command.expect("GUI dispatch handles a missing command");
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| output.exit_error(&format!("could not start runtime: {error}"), 1))
        .block_on(app::run(command, conf, config_file, client, output));
}
