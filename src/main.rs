mod clpboard;
mod password;
mod config;
use clap::{Args, Parser, Subcommand};
use clpboard::*;
use password::*;
use config::*;


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
    Config(ConfigArgs)
}

#[derive(Args)]
struct GenpassArgs {
    #[arg(short, long)]
    length: Option<u8>,
    #[arg(long("no-stats"))]
    no_stats: Option<bool>,
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
struct ConfigArgs{
    #[arg(long)]
    defalt:bool,
    #[arg(long("genpass-length"))]
    genpass_length:Option<u8>,
    #[arg(long("genpass-no-stats"))]
    genpass_no_stats:Option<bool>,
    #[arg(long("clpb-timeout"))]
    clpb_timeout:Option<u8>

}

fn main() {
    let cli = Cli::parse();
    let conf=read_config();

    match cli.command {
        Some(Commands::Genpass(command)) => gen_pass(command.length.unwrap_or(conf.genpass.length), command.no_stats.unwrap_or(conf.genpass.no_stats)),
        Some(Commands::Passcheck(command)) => pass_str(&command.password),
        Some(Commands::Clpb(command)) => cpy("testpass", command.timeout.unwrap_or(conf.clpboard.timeout)),
        Some(Commands::Config(command)) => update(command),
        None => println!("no args todo gui"),
    }
}
