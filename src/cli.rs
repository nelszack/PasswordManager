use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
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
    },
    Passcheck {
        #[arg(short, long)]
        password: String,
    },
    Clpb {
        #[command(flatten)]
        timeout: Timeout,
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
    Run {
        #[arg(long)]
        key: Option<String>,
    },
    Kill,
    Delete(DeleteArgs),
    New {
        #[arg(long)]
        key_path: Option<String>,
    },
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: String,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        notes: Option<String>,
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
}

#[derive(Args, Debug)]
pub struct Timeout {
    #[arg(long)]
    pub timeout: Option<u8>,
}

#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[arg(long)]
    pub defalt: bool,
    #[arg(long("genpass-length"))]
    pub genpass_length: Option<u8>,
    #[arg(long("genpass-stats"))]
    pub genpass_stats: Option<bool>,
    #[arg(long("clpb-timeout"))]
    pub clpb_timeout: Option<u8>,
}

#[derive(Serialize, Deserialize, Debug, Args)]
pub struct UpdateArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub username: Option<String>,
    #[arg(long)]
    pub password: Option<String>,
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub notes: Option<String>,
}

#[derive(Args, Debug)]
pub struct DeleteArgs {
    #[arg(
        long,
        conflicts_with = "entry_name",
        required_unless_present = "entry_name"
    )]
    pub id: Option<u64>,
    #[arg(long, conflicts_with = "id", required_unless_present = "id")]
    pub entry_name: Option<String>,
}
