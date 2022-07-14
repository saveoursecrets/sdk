use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sos_check::{keys, status, verify_vault, verify_wal, Result};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Utility tool to check status and integrity.
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
        /// Print the root commit hash.
        #[clap(short, long)]
        root: bool,

        /// Print the commit hash for each row.
        #[clap(short, long)]
        commits: bool,

        /// Vault file path.
        file: PathBuf,
    },
    /// Print the vault header and root commit hash.
    Status {
        /// Vault file path.
        file: PathBuf,
    },
    /// Print the vault keys.
    Keys {
        /// Vault file path.
        file: PathBuf,
    },
    /// Write ahead log tools.
    Wal {
        #[clap(subcommand)]
        cmd: Wal,
    },
}

#[derive(Subcommand, Debug)]
enum Wal {
    /// Verify the integrity of a WAL file.
    Verify {
        /// Print the root commit hash.
        #[clap(short, long)]
        root: bool,

        /// Print the commit hash for each row.
        #[clap(short, long)]
        commits: bool,

        /// Write ahead log file path.
        file: PathBuf,
    },
}

fn run() -> Result<()> {
    let args = Cli::parse();
    match args.cmd {
        Command::Verify {
            file,
            root,
            commits,
        } => {
            verify_vault(file, root, commits)?;
        }
        Command::Status { file } => status(file)?,
        Command::Keys { file } => keys(file)?,
        Command::Wal { cmd } => match cmd {
            Wal::Verify {
                file,
                root,
                commits,
            } => {
                verify_wal(file, root, commits)?;
            }
        },
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
