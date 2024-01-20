use clap::Subcommand;
use std::path::PathBuf;

use sos_net::sdk::{
    commit::{event_log_commit_tree_file, vault_commit_tree_file},
    decode, hex,
    vault::{Header, Vault},
    vfs,
};

use crate::{Error, Result};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Verify vault row checksums.
    Vault {
        /// Print the checksums for each row.
        #[clap(short, long)]
        verbose: bool,

        /// Vault file path.
        file: PathBuf,
    },
    /// Print a vault file header.
    Header {
        /// Vault file path.
        file: PathBuf,
    },
    /// Print the vault keys.
    Keys {
        /// Vault file path.
        file: PathBuf,
    },
    /// Verify log file checksums.
    Log {
        /// Print more information.
        #[clap(short, long)]
        verbose: bool,

        /// Log file path.
        file: PathBuf,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Vault { file, verbose } => {
            verify_vault(file, verbose).await?;
        }
        Command::Header { file } => header(file).await?,
        Command::Keys { file } => keys(file).await?,
        Command::Log { verbose, file } => {
            verify_log(file, verbose).await?;
        }
    }

    Ok(())
}

/// Verify the integrity of a vault.
async fn verify_vault(file: PathBuf, verbose: bool) -> Result<()> {
    if !vfs::metadata(&file).await?.is_file() {
        return Err(Error::NotFile(file));
    }
    vault_commit_tree_file(&file, true, |row_info| {
        if verbose {
            println!("{}", hex::encode(row_info.commit()));
        }
    })
    .await?;
    println!("Verified ✓");
    Ok(())
}

/// Verify the integrity of a log file.
async fn verify_log(file: PathBuf, verbose: bool) -> Result<()> {
    if !vfs::metadata(&file).await?.is_file() {
        return Err(Error::NotFile(file));
    }
    let tree = event_log_commit_tree_file(&file, true, |row_info| {
        if verbose {
            println!("hash: {}", hex::encode(row_info.commit()));
        }
    })
    .await?;
    if verbose {
        if let Some(root) = tree.root() {
            println!("root: {}", root);
        }
    }
    println!("Verified {} commit(s) ✓", tree.len());
    Ok(())
}

/// Print a vault header.
pub async fn header(vault: PathBuf) -> Result<()> {
    if !vfs::metadata(&vault).await?.is_file() {
        return Err(Error::NotFile(vault));
    }

    let header = Header::read_header_file(&vault).await?;
    println!("{}", header);
    Ok(())
}

/// Print the vault keys.
pub async fn keys(vault: PathBuf) -> Result<()> {
    if !vfs::metadata(&vault).await?.is_file() {
        return Err(Error::NotFile(vault));
    }

    let buffer = vfs::read(&vault).await?;
    let vault: Vault = decode(&buffer).await?;
    for id in vault.keys() {
        println!("{}", id);
    }

    Ok(())
}
