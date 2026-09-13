use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[derive(Parser, Debug)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<CliCommands>,
}
pub fn cli_parse() -> Cli {
    Cli::parse()
}
#[derive(Subcommand, Debug)]
pub enum CliCommands {
    Genpass {
        #[arg(short, long)]
        length: Option<u8>,
        #[arg(long("no-stats"), default_value_t = false, conflicts_with = "stats")]
        no_stats: bool,
        #[arg(long("stats"), default_value_t = false)]
        stats: bool,
        #[arg(long("no-copy"), default_value_t = false, conflicts_with = "copy")]
        no_copy: bool,
        #[arg(long("copy"), default_value_t = false)]
        copy: bool,
        #[arg(long)]
        copy_time: Option<u8>,
        #[arg(long)]
        no_uppercase: bool,
        #[arg(long)]
        no_lowercase: bool,
        #[arg(long)]
        no_digits: bool,
        #[arg(long)]
        no_symbols: bool,
        #[arg(long)]
        symbols: Option<String>,
        #[arg(long)]
        exclude_ambiguous: bool,
        #[arg(long, conflicts_with = "length")]
        passphrase: bool,
        #[arg(long, default_value_t = 6, requires = "passphrase")]
        words: u8,
        #[arg(long, default_value = "-", requires = "passphrase")]
        separator: String,
    },
    Passcheck {
        #[arg(short, long)]
        password: String,
    },
    Config(ConfigArgs),
    Unlock {
        #[arg(long)]
        key: Option<String>,

        #[command(flatten)]
        timeout: Timeout,
    },
    Lock,
    Status,
    Start,
    #[command(hide = true)]
    Run,
    /// Install or run the browser native-messaging bridge.
    NativeHost {
        #[command(subcommand)]
        command: NativeHostCommands,
    },
    Kill,
    Delete(DeleteArgs),
    History {
        #[command(flatten)]
        target: EntryArgs,
    },
    RestorePassword {
        #[command(flatten)]
        target: EntryArgs,
        #[arg(long)]
        revision: usize,
    },
    Trash,
    Restore {
        #[arg(long)]
        id: usize,
    },
    Purge(PurgeArgs),
    Audit,
    Totp {
        #[command(subcommand)]
        command: TotpCommands,
    },
    /// Create or restore a complete encrypted vault backup.
    Backup {
        #[command(subcommand)]
        command: BackupCommands,
    },
    New {
        #[arg(long = "key")]
        key_path: Option<String>,
    },
    /// Re-encrypt the unlocked vault with a new master password or key file.
    Rekey {
        #[arg(long = "key")]
        key_path: Option<String>,
    },
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long = "generate-password")]
        generate_password: bool,
        #[arg(long)]
        #[arg(long("no-copy"), default_value_t = false, conflicts_with = "copy")]
        no_copy: bool,
        #[arg(long("copy"), default_value_t = false)]
        copy: bool,
    },
    View,
    Search(SearchArgs),
    Update {
        #[command(flatten)]
        add: UpdateArgs,
        #[command(flatten)]
        target: EntryArgs,
    },
    Get {
        #[command(flatten)]
        target: EntryArgs,
    },
    Import {
        #[arg(long)]
        path: String,
        #[arg(long)]
        new: bool,
        #[arg(long = "key")]
        key_path: Option<String>,
    },
    Export {
        #[arg(long)]
        path: String,
    },
    Completions {
        #[arg(value_enum)]
        shell: Shell,
        #[arg(long, default_value = "-")]
        output: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum NativeHostCommands {
    /// Register the native host for an unpacked Chrome-family extension.
    Install {
        /// The 32-character ID shown for the extension on chrome://extensions.
        #[arg(long)]
        extension_id: String,
        #[arg(long, value_enum, default_value_t = NativeBrowser::Chrome)]
        browser: NativeBrowser,
    },
    #[command(hide = true)]
    Run,
}

#[derive(Subcommand, Debug)]
pub enum BackupCommands {
    /// Export every vault record to a versioned encrypted backup.
    Create {
        #[arg(long)]
        path: String,
        /// Encrypt with an existing key file instead of a backup password.
        #[arg(long = "key")]
        key_path: Option<String>,
        /// Atomically replace an existing backup file.
        #[arg(long)]
        force: bool,
    },
    /// Restore a complete backup as the vault associated with its password/key.
    Restore {
        #[arg(long)]
        path: String,
        /// Decrypt with a key file instead of a backup password.
        #[arg(long = "key")]
        key_path: Option<String>,
        /// Replace an existing vault associated with the backup password/key.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum NativeBrowser {
    Chrome,
    Chromium,
    Helium,
}

#[derive(Args, Debug)]
pub struct Timeout {
    #[arg(long, value_parser = parse_duration)]
    pub timeout: Option<u64>,
}

#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[arg(long)]
    pub reset: bool,
    #[arg(long = "length")]
    pub genpass_length: Option<u8>,
    #[arg(long = "stats")]
    pub genpass_stats: Option<bool>,
    #[arg(long = "copy")]
    pub genpass_copy: Option<bool>,
    #[arg(long)]
    pub clipboard_timeout: Option<u8>,
    #[arg(long)]
    #[arg(value_parser = parse_duration)]
    pub unlock_timeout: Option<u64>,
}

fn parse_duration(value: &str) -> Result<u64, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("duration cannot be empty".to_string());
    }
    let (number, multiplier) = match value.as_bytes().last().copied() {
        Some(b's') => (&value[..value.len() - 1], 1),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 60 * 60),
        Some(b'd') => (&value[..value.len() - 1], 24 * 60 * 60),
        Some(byte) if byte.is_ascii_digit() => (value, 1),
        _ => return Err("use seconds or a suffix such as 15m, 1h, or 1d".to_string()),
    };
    number
        .parse::<u64>()
        .map_err(|_| "duration must be a positive whole number".to_string())?
        .checked_mul(multiplier)
        .ok_or_else(|| "duration is too large".to_string())
}

#[derive(Serialize, Deserialize, Debug, Args)]
pub struct UpdateArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long, default_value_t = false)]
    pub password: bool,
    #[arg(
        long = "generate-password",
        default_value_t = false,
        requires = "password"
    )]
    pub generate_password: bool,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub notes: Option<String>,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    #[arg(
        long,
        conflicts_with_all = ["vault", "entry_name"],
        required_unless_present_any = ["entry_name", "vault"]
    )]
    pub id: Option<usize>,
    #[arg(long, conflicts_with_all = ["id","vault"], required_unless_present_any=["id", "vault" ])]
    pub entry_name: Option<String>,
    #[arg(long, conflicts_with_all = ["id","entry_name"], required_unless_present_any=["id", "entry_name" ])]
    pub vault: bool,
    #[arg(long, requires = "vault")]
    pub key: Option<String>,
}

#[derive(Args, Debug)]
pub struct PurgeArgs {
    #[arg(long, conflicts_with = "all", required_unless_present = "all")]
    pub id: Option<usize>,
    #[arg(long, conflicts_with = "id", required_unless_present = "id")]
    pub all: bool,
}

#[derive(Args, Debug)]
pub struct SearchArgs {
    /// Case-insensitive text matched across name, username, URL, and notes.
    #[arg(required_unless_present_any = ["name", "username", "url", "notes"])]
    pub query: Option<String>,
    /// Require this text in the entry name.
    #[arg(long)]
    pub name: Option<String>,
    /// Require this text in the username.
    #[arg(long)]
    pub username: Option<String>,
    /// Require this text in the URL.
    #[arg(long)]
    pub url: Option<String>,
    /// Require this text in the notes.
    #[arg(long)]
    pub notes: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum TotpCommands {
    /// Store a Base32 secret or otpauth URI using a hidden prompt.
    Set {
        #[command(flatten)]
        target: EntryArgs,
    },
    /// Generate the current authentication code.
    Show {
        #[command(flatten)]
        target: EntryArgs,
        #[arg(long)]
        copy: bool,
        #[arg(long, requires = "copy")]
        copy_time: Option<u8>,
    },
    /// Remove the authenticator configuration from an entry.
    Remove {
        #[command(flatten)]
        target: EntryArgs,
    },
}

#[derive(Args, Debug)]
pub struct EntryArgs {
    #[arg(
        long,
        conflicts_with = "entry_name",
        required_unless_present = "entry_name"
    )]
    pub id: Option<usize>,
    #[arg(long, conflicts_with = "id", required_unless_present = "id")]
    pub entry_name: Option<String>,
}

#[cfg(test)]
mod test {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_get_by_entry_name_parses() {
        let cli = Cli::try_parse_from(["pm", "get", "--entry-name", "foo"]).unwrap();
        match cli.command {
            Some(CliCommands::Get { target }) => {
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
            Some(CliCommands::Get { target }) => {
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

        assert!(
            Cli::try_parse_from(["pm", "totp", "show", "--id", "7", "--copy-time", "20"]).is_err()
        );
    }
}
