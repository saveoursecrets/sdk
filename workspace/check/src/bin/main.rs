use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sos_check::{verify, Result};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

//use terminal_banner::{Banner, Padding};

/// Tool to check the status and verify the integrity of vaults.
#[derive(Parser, Debug)]
#[clap(name = "sos-check", author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Verify the integrity of a vault.
    Verify {
        /// Print the root hash.
        #[clap(short, long)]
        root: bool,

        /// Print the commit hash for each row.
        #[clap(short, long)]
        commits: bool,

        /// Vault file path.
        vault: PathBuf,
    },
}

fn run() -> Result<()> {
    let args = Cli::parse();
    match args.cmd {
        Command::Verify {
            vault,
            root,
            commits,
        } => {
            verify(vault, root, commits)?;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "sos_check=info".into()),
        ))
        .with(tracing_subscriber::fmt::layer().without_time())
        .init();

    match run() {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("{}", e);
        }
    }
    Ok(())
}
