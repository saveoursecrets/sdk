use clap::Subcommand;
use std::path::{Path, PathBuf};

use sos_sdk::{
    commit::{vault_commit_tree_file, wal_commit_tree_file, CommitTree},
    formats::vault_iter,
    hex,
    uuid::Uuid,
    vault::Header,
    wal::WalItem,
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

pub fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Vault { file, verbose } => {
            verify_vault(file, verbose)?;
        }
        Command::Header { file } => header(file)?,
        Command::Keys { file } => keys(file)?,
        Command::Log { verbose, file } => {
            verify_log(file, verbose)?;
        }
    }

    Ok(())
}

/// Verify the integrity of a vault.
fn verify_vault(file: PathBuf, verbose: bool) -> Result<()> {
    if !file.is_file() {
        return Err(Error::NotFile(file));
    }
    let tree = vault_commit_tree_file(&file, true, |row_info| {
        if verbose {
            println!("{}", hex::encode(row_info.commit()));
        }
    })?;
    println!("Verified ✓");
    Ok(())
}

/// Verify the integrity of a log file.
fn verify_log(file: PathBuf, verbose: bool) -> Result<()> {
    if !file.is_file() {
        return Err(Error::NotFile(file));
    }
    let tree = wal_commit_tree_file(&file, true, |row_info| {
        if verbose {
            println!("{}", hex::encode(row_info.commit()));
        }
    })?;
    if verbose {
        if let Some(root) = tree.root_hex() {
            println!("{}", root);
        }
    }
    println!("Verified ✓");
    Ok(())
}

/// Print a vault header.
pub fn header(vault: PathBuf) -> Result<()> {
    if !vault.is_file() {
        return Err(Error::NotFile(vault));
    }

    let header = Header::read_header_file(&vault)?;
    println!("{}", header);
    Ok(())
}

/// Print the vault keys.
pub fn keys(vault: PathBuf) -> Result<()> {
    if !vault.is_file() {
        return Err(Error::NotFile(vault));
    }

    let it = vault_iter(&vault)?;
    for record in it {
        let record = record?;
        let id = Uuid::from_bytes(record.id());
        println!("{}", id);
    }
    Ok(())
}
