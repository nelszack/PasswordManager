mod clpboard;
mod config;
mod encryption;
mod files;
mod password;
mod vault;
mod background;
use clap::{Args, Parser, Subcommand};
use clpboard::*;
use config::*;
// use encryption::*;
use files::*;
use password::*;
use vault::*;
use background::*;
use serde::{Serialize, Deserialize};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}
#[derive(Subcommand)]
enum Commands {
    Genpass(GenpassArgs),
    Passcheck(PasscheckArgs),
    Clpb(ClpbArgs),
    Config(ConfigArgs),
    // Unlock(UnlockArgs),
    Create(CreateArgs),
    Background(BackgroundArgs),
    Server(UnlockArgs)
    
}
#[derive(Subcommand)]
#[derive(Serialize, Deserialize)]
enum  ServerCommands {
    Start(BackgroundArgs),
    Unlock,
    Lock,
    Kill,
    Status,
    Run(BackgroundArgs)
}
#[derive(Args)]
struct GenpassArgs {
    #[arg(short, long)]
    length: Option<u8>,
    #[arg(long("no-stats"), default_value_t = false, conflicts_with = "stats")]
    no_stats: bool,
    #[arg(long("stats"), default_value_t = false)]
    stats: bool,
}
#[derive(Args)]
struct PasscheckArgs {
    password: String,
}
#[derive(Args)]
struct ClpbArgs {
    #[arg(short, long)]
    timeout: Option<u8>,
}
#[derive(Args)]
#[derive(Serialize, Deserialize)]
struct UnlockArgs {
    #[command(subcommand)]
    command:ServerCommands,
    #[arg(short, long)]
    key: Option<String>,
    
}




#[derive(Args)]
#[derive(Serialize, Deserialize)]
struct BackgroundArgs{
     #[arg(short, long, default_value_t = 100)]
     time:u64
}
#[derive(Args)]
struct CreateArgs {
    #[arg(long("key"))]
    key_file: Option<String>,
}
#[derive(Args)]
struct ConfigArgs {
    #[arg(long)]
    defalt: bool,
    #[arg(long("genpass-length"))]
    genpass_length: Option<u8>,
    #[arg(long("genpass-stats"))]
    genpass_stats: Option<bool>,
    #[arg(long("clpb-timeout"))]
    clpb_timeout: Option<u8>,
}

fn main() {
    let cli = Cli::parse();
    let mut conf = read_config();

    match cli.command {
        Some(Commands::Genpass(command)) => {
            if command.stats {
                conf.genpass.stats = true
            };
            if command.no_stats {
                conf.genpass.stats = false
            };
            gen_pass(
                command.length.unwrap_or(conf.genpass.length),
                conf.genpass.stats,
            )
        }
        Some(Commands::Passcheck(command)) => pass_str(&command.password),
        Some(Commands::Clpb(command)) => {
            cpy("testpass", command.timeout.unwrap_or(conf.clpboard.timeout))
        }
        Some(Commands::Config(command)) => update(command),
        Some(Commands::Create(command)) => create_vault(command),
        // Some(Commands::Background(commands))=>panic!("not done yet"),
        Some(Commands::Server(commands)) => manager(commands),
        None => println!("no args todo gui"),
        _=>panic!("not done yet")
    }
}
