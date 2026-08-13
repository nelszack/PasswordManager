use clap::{Args, Parser, Subcommand};
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
    Kill,
    Delete(DeleteArgs),
    New {
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
        gen_password: bool,
        #[arg(long)]
        #[arg(long("no-copy"), default_value_t = false, conflicts_with = "copy")]
        no_copy: bool,
        #[arg(long("copy"), default_value_t = false)]
        copy: bool,
    },
    View,
    Update {
        #[command(flatten)]
        add: UpdateArgs,
        #[command(flatten)]
        which: DeleteArgs,
    },
    Get {
        #[command(flatten)]
        which: DeleteArgs,
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

#[derive(Args, Debug)]
pub struct Timeout {
    #[arg(long)]
    pub timeout: Option<u8>,
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
    pub unlock_timeout: Option<u8>,
}

#[derive(Serialize, Deserialize, Debug, Args)]
pub struct UpdateArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long, default_value_t = false)]
    pub password: bool,
    #[arg(long = "generate-password", default_value_t = false, requires = "password")]
    pub gen_password: bool,
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

#[cfg(test)]
mod test {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_get_by_entry_name_parses() {
        let cli = Cli::try_parse_from(["pm", "get", "--entry-name", "foo"]).unwrap();
        match cli.command {
            Some(CliCommands::Get { which }) => {
                assert_eq!(which.id, None);
                assert_eq!(which.entry_name.as_deref(), Some("foo"));
            }
            _ => panic!("expected Get command"),
        }
    }

    #[test]
    fn test_delete_by_entry_name_parses() {
        let cli = Cli::try_parse_from(["pm", "delete", "--entry-name", "foo"]).unwrap();
        match cli.command {
            Some(CliCommands::Delete(which)) => {
                assert_eq!(which.id, None);
                assert_eq!(which.entry_name.as_deref(), Some("foo"));
            }
            _ => panic!("expected Delete command"),
        }
    }

    #[test]
    fn test_update_by_entry_name_parses() {
        let cli = Cli::try_parse_from(["pm", "update", "--name", "new", "--entry-name", "foo"]).unwrap();
        match cli.command {
            Some(CliCommands::Update { which, .. }) => {
                assert_eq!(which.id, None);
                assert_eq!(which.entry_name.as_deref(), Some("foo"));
            }
            _ => panic!("expected Update command"),
        }
    }

    #[test]
    fn test_get_by_id_parses() {
        let cli = Cli::try_parse_from(["pm", "get", "--id", "3"]).unwrap();
        match cli.command {
            Some(CliCommands::Get { which }) => {
                assert_eq!(which.id, Some(3));
                assert_eq!(which.entry_name, None);
            }
            _ => panic!("expected Get command"),
        }
    }

    #[test]
    fn test_get_by_vault_parses() {
        let cli = Cli::try_parse_from(["pm", "get", "--vault", "--key", "k.bin"]).unwrap();
        match cli.command {
            Some(CliCommands::Get { which }) => assert!(which.vault),
            _ => panic!("expected Get command"),
        }
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
}
