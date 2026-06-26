use anyhow::Result;
use clap::Parser;

mod baseline;
mod client;
mod cmd;
mod config;
mod lockfile;
mod waiver;

#[derive(Parser, Debug)]
#[command(
    name = "pkgradar",
    version,
    about = "PkgRadar CI gate and static package scanner",
    long_about = "Wraps the PkgRadar HTTP API for CI pipelines, pre-commit \
                  hooks, and local checks. Issue a token at \
                  https://pkgradar.com/dashboard/keys."
)]
struct Cli {
    #[command(subcommand)]
    command: cmd::Command,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let code = match run(cli).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("pkgradar: {err:#}");
            3
        }
    };
    std::process::exit(code);
}

async fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        cmd::Command::Gate(args) => cmd::gate::run(args).await,
        cmd::Command::Scan(args) => cmd::scan::run(args).await,
        cmd::Command::Version => cmd::version::run(),
    }
}
