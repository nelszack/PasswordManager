use super::*;
use clap::{Command, CommandFactory, Parser};

fn assert_complete_help(command: &Command, path: &str) {
    for argument in command.get_arguments() {
        let id = argument.get_id().as_str();
        if !matches!(id, "help" | "version") && argument.get_help().is_none() {
            panic!("{path}: argument `{id}` has no help text");
        }
    }

    for subcommand in command.get_subcommands() {
        if subcommand.is_hide_set() {
            continue;
        }
        let subcommand_path = format!("{path} {}", subcommand.get_name());
        assert!(
            subcommand.get_about().is_some(),
            "{subcommand_path}: command has no description"
        );
        assert_complete_help(subcommand, &subcommand_path);
    }
}

#[test]
fn every_visible_command_and_argument_has_help_text() {
    assert_complete_help(&Cli::command(), "pm");
}

#[test]
fn global_port_override_parses_and_rejects_zero() {
    let cli = Cli::try_parse_from(["pm", "--port", "8787", "status"]).unwrap();
    assert_eq!(cli.port, Some(8787));
    assert!(Cli::try_parse_from(["pm", "status", "--port", "0"]).is_err());
}

#[test]
fn server_port_config_option_parses() {
    let cli = Cli::try_parse_from(["pm", "config", "--server-port", "8989"]).unwrap();
    let Some(CliCommands::Config(config)) = cli.command else {
        panic!("expected config command");
    };
    assert_eq!(config.server_port, Some(8989));
}

#[test]
fn test_get_by_entry_name_parses() {
    let cli = Cli::try_parse_from(["pm", "get", "--entry-name", "foo"]).unwrap();
    match cli.command {
        Some(CliCommands::Get { target, .. }) => {
            assert_eq!(target.id, None);
            assert_eq!(target.entry_name.as_deref(), Some("foo"));
        }
        _ => panic!("expected Get command"),
    }
}

#[test]
fn test_delete_by_entry_name_parses() {
    let cli = Cli::try_parse_from(["pm", "delete", "--entry-name", "foo"]).unwrap();
    match cli.command {
        Some(CliCommands::Delete(target)) => {
            assert_eq!(target.id, None);
            assert_eq!(target.entry_name.as_deref(), Some("foo"));
        }
        _ => panic!("expected Delete command"),
    }
}

#[test]
fn test_delete_vault_keep_key_requires_a_key_file() {
    let cli = Cli::try_parse_from([
        "pm",
        "delete",
        "--vault",
        "--key",
        "./shared.key",
        "--keep-key",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Some(CliCommands::Delete(DeleteArgs { keep_key: true, .. }))
    ));
    assert!(Cli::try_parse_from(["pm", "delete", "--vault", "--keep-key"]).is_err());
}

#[test]
fn test_update_by_entry_name_parses() {
    let cli =
        Cli::try_parse_from(["pm", "update", "--name", "new", "--entry-name", "foo"]).unwrap();
    match cli.command {
        Some(CliCommands::Update { target, .. }) => {
            assert_eq!(target.id, None);
            assert_eq!(target.entry_name.as_deref(), Some("foo"));
        }
        _ => panic!("expected Update command"),
    }
}

#[test]
fn test_get_by_id_parses() {
    let cli = Cli::try_parse_from(["pm", "get", "--id", "3"]).unwrap();
    match cli.command {
        Some(CliCommands::Get { target, .. }) => {
            assert_eq!(target.id, Some(3));
            assert_eq!(target.entry_name, None);
        }
        _ => panic!("expected Get command"),
    }
}

#[test]
fn test_get_rejects_vault_target() {
    assert!(Cli::try_parse_from(["pm", "get", "--vault", "--key", "k.bin"]).is_err());
}

#[test]
fn test_delete_requires_target() {
    assert!(Cli::try_parse_from(["pm", "delete"]).is_err());
}

#[test]
fn test_genpass_parses() {
    let cli = Cli::try_parse_from(["pm", "genpass", "--length", "20", "--copy"]).unwrap();
    match cli.command {
        Some(CliCommands::Genpass {
            length,
            copy,
            no_copy,
            ..
        }) => {
            assert_eq!(length, Some(20));
            assert!(copy);
            assert!(!no_copy);
        }
        _ => panic!("expected Genpass command"),
    }
}

#[test]
fn generator_rejects_empty_and_ignored_option_combinations() {
    assert!(Cli::try_parse_from(["pm", "genpass", "--length", "0"]).is_err());
    assert!(Cli::try_parse_from(["pm", "genpass", "--passphrase", "--words", "0"]).is_err());
    assert!(Cli::try_parse_from(["pm", "genpass", "--no-symbols", "--symbols", "abc"]).is_err());
    assert!(Cli::try_parse_from(["pm", "genpass", "--passphrase", "--no-uppercase"]).is_err());
}

#[test]
fn config_reset_is_exclusive_and_noop_is_detectable() {
    assert!(!ConfigArgs::default().has_updates());
    assert!(Cli::try_parse_from(["pm", "config", "--reset"]).is_ok());
    assert!(Cli::try_parse_from(["pm", "config", "--reset", "--length", "24"]).is_err());
}

#[test]
fn passcheck_can_prompt_and_command_aliases_parse() {
    assert!(Cli::try_parse_from(["pm", "passcheck"]).is_ok());
    assert!(matches!(
        Cli::try_parse_from(["pm", "list"]).unwrap().command,
        Some(CliCommands::View(_))
    ));
    assert!(matches!(
        Cli::try_parse_from(["pm", "init"]).unwrap().command,
        Some(CliCommands::New { .. })
    ));
}

#[test]
fn test_completions_parses() {
    let cli = Cli::try_parse_from(["pm", "completions", "bash"]).unwrap();
    match cli.command {
        Some(CliCommands::Completions { shell, output }) => {
            assert!(matches!(shell, Shell::Bash));
            assert_eq!(output.to_string_lossy(), "-");
        }
        _ => panic!("expected Completions command"),
    }
}

#[test]
fn test_native_host_install_parses() {
    let cli = Cli::try_parse_from([
        "pm",
        "native-host",
        "install",
        "--extension-id",
        "abcdefghijklmnopabcdefghijklmnop",
        "--browser",
        "chromium",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Some(CliCommands::NativeHost {
            command: NativeHostCommands::Install {
                browser: NativeBrowser::Chromium,
                ..
            }
        })
    ));
}

#[test]
fn test_encrypted_backup_commands_parse() {
    let create = Cli::try_parse_from([
        "pm",
        "backup",
        "create",
        "--path",
        "vault.pmbackup",
        "--force",
    ])
    .unwrap();
    assert!(matches!(
        create.command,
        Some(CliCommands::Backup {
            command: BackupCommands::Create { force: true, .. }
        })
    ));

    let restore = Cli::try_parse_from([
        "pm",
        "backup",
        "restore",
        "--path",
        "vault.pmbackup",
        "--key",
        "backup.key",
    ])
    .unwrap();
    assert!(matches!(
        restore.command,
        Some(CliCommands::Backup {
            command: BackupCommands::Restore {
                key_path: Some(_),
                ..
            }
        })
    ));
}

#[test]
fn test_human_duration_parses() {
    assert_eq!(parse_duration("90").unwrap(), 90);
    assert_eq!(parse_duration("15m").unwrap(), 900);
    assert_eq!(parse_duration("2h").unwrap(), 7200);
    assert_eq!(parse_duration("1d").unwrap(), 86400);
    assert!(parse_duration("later").is_err());
}

#[test]
fn test_search_query_and_filters_parse() {
    let cli = Cli::try_parse_from(["pm", "search", "github", "--username", "alice"]).unwrap();
    match cli.command {
        Some(CliCommands::Search(args)) => {
            assert_eq!(args.query.as_deref(), Some("github"));
            assert_eq!(args.username.as_deref(), Some("alice"));
        }
        _ => panic!("expected Search command"),
    }
    assert!(Cli::try_parse_from(["pm", "search"]).is_err());
    assert!(Cli::try_parse_from(["pm", "search", "--stale-days", "90"]).is_ok());
}

#[test]
fn security_health_options_parse() {
    let cli = Cli::try_parse_from([
        "pm",
        "audit",
        "--stale-days",
        "365",
        "--breaches",
        "--require-totp",
    ])
    .unwrap();
    assert!(matches!(
        cli.command,
        Some(CliCommands::Audit {
            stale_days: Some(365),
            breaches: true,
            require_totp: true,
        })
    ));
}

#[test]
fn typed_items_multiple_urls_and_list_options_parse() {
    let add = Cli::try_parse_from([
        "pm",
        "add",
        "--name",
        "Office Wi-Fi",
        "--type",
        "wifi",
        "--url",
        "https://router.example",
        "--url",
        "https://backup-router.example",
    ])
    .unwrap();
    assert!(matches!(
        add.command,
        Some(CliCommands::Add {
            kind: ItemKind::Wifi,
            url,
            ..
        }) if url.len() == 2
    ));

    let view = Cli::try_parse_from([
        "pm",
        "view",
        "--type",
        "payment-card",
        "--sort",
        "modified",
        "--descending",
    ])
    .unwrap();
    assert!(matches!(
        view.command,
        Some(CliCommands::View(ListArgs {
            kind: Some(ItemKind::PaymentCard),
            sort: SortField::Modified,
            descending: true,
            ..
        }))
    ));

    assert!(Cli::try_parse_from(["pm", "search", "--type", "secure-note"]).is_ok());
    assert!(
        Cli::try_parse_from(["pm", "update", "--id", "1", "--url", "a", "--clear-urls"]).is_err()
    );

    let scripted =
        Cli::try_parse_from(["pm", "--json", "get", "--id", "2", "--password-only"]).unwrap();
    assert!(scripted.json);
    assert!(matches!(
        scripted.command,
        Some(CliCommands::Get {
            password_only: true,
            ..
        })
    ));

    let import = Cli::try_parse_from([
        "pm",
        "import",
        "--path",
        "vault.csv",
        "--preview",
        "--conflicts",
        "replace",
    ])
    .unwrap();
    assert!(matches!(
        import.command,
        Some(CliCommands::Import {
            preview: true,
            conflicts: crate::types::ConflictPolicy::Replace,
            ..
        })
    ));
    assert!(
        Cli::try_parse_from(["pm", "import", "--path", "vault.csv", "--key", "key.bin"]).is_err()
    );

    assert!(
        Cli::try_parse_from([
            "pm",
            "update",
            "--id",
            "1",
            "--field",
            "environment=production",
            "--secret-field",
            "token",
        ])
        .is_ok()
    );
}

#[test]
fn test_totp_commands_parse() {
    let set = Cli::try_parse_from(["pm", "totp", "set", "--id", "7"]).unwrap();
    assert!(matches!(
        set.command,
        Some(CliCommands::Totp {
            command: TotpCommands::Set { .. }
        })
    ));

    let show = Cli::try_parse_from([
        "pm",
        "totp",
        "show",
        "--entry-name",
        "github",
        "--copy",
        "--copy-time",
        "20",
    ])
    .unwrap();
    assert!(matches!(
        show.command,
        Some(CliCommands::Totp {
            command: TotpCommands::Show {
                copy: true,
                copy_time: Some(20),
                ..
            }
        })
    ));

    assert!(Cli::try_parse_from(["pm", "totp", "show", "--id", "7", "--copy-time", "20"]).is_err());
}
