use std::path::PathBuf;

use clap::Subcommand;
use super::{keys, status, verify_vault, verify_wal};
use crate::Result;

#[derive(Subcommand, Debug)]
pub enum Command {
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
pub enum Wal {
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

pub fn run(cmd: Command) -> Result<()> {
    match cmd {
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
