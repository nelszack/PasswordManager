mod password;
use clap::{Args, Parser, Subcommand};
use password::*;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}
#[derive(Subcommand)]
enum Commands {
    Genpass(GenpassArgs),
    Passcheck(PasscheckArgs),
}

#[derive(Args)]
struct GenpassArgs {
    #[arg(short, long, default_value_t = 12)]
    length: u8,
    #[arg(long("no-stats"), default_value_t = false)]
    stats: bool,
}
#[derive(Args)]
struct PasscheckArgs {
    password: String,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Genpass(command)) => gen_pass(command.length, command.stats),
        Some(Commands::Passcheck(command)) => pass_str(command.password),
        None => println!("no args todo gui"),
    }
}
