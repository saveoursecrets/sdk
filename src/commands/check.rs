use std::path::{PathBuf, Path};
use clap::Subcommand;

use sos_core::{
    commit::{vault_commit_tree_file, wal_commit_tree_file, CommitTree},
    formats::vault_iter,
    hex, uuid::Uuid,
    vault::Header,
    wal::WalItem,
};

use crate::{Error, Result};

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

/// Verify the integrity of a vault.
fn verify_vault(file: PathBuf, root: bool, commits: bool) -> Result<()> {
    if !file.is_file() {
        return Err(Error::NotFile(file));
    }
    let tree = vault_commit_tree_file(&file, true, |row_info| {
        if commits {
            println!("{}", hex::encode(row_info.commit()));
        }
    })?;
    if root {
        if let Some(root) = tree.root_hex() {
            println!("{}", root);
        }
    }
    println!("Verified ✓");
    Ok(())
}

/// Verify the integrity of a WAL file.
fn verify_wal(file: PathBuf, root: bool, commits: bool) -> Result<()> {
    if !file.is_file() {
        return Err(Error::NotFile(file));
    }
    let tree = wal_commit_tree_file(&file, true, |row_info| {
        if commits {
            println!("{}", hex::encode(row_info.commit()));
        }
    })?;
    if root {
        if let Some(root) = tree.root_hex() {
            println!("{}", root);
        }
    }
    println!("Verified ✓");
    Ok(())
}

/// Print the vault header and root commit.
fn status(vault: PathBuf) -> Result<()> {
    if !vault.is_file() {
        return Err(Error::NotFile(vault));
    }

    let header = Header::read_header_file(&vault)?;
    let tree = build_tree(&vault)?;

    println!("{}", header);
    if let Some(root) = tree.root_hex() {
        println!("Commit: {}", root);
    }
    Ok(())
}

/// Print the vault keys.
fn keys(vault: PathBuf) -> Result<()> {
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

/// Build a commit tree from the commit hashes in a vault file.
fn build_tree<P: AsRef<Path>>(path: P) -> Result<CommitTree> {
    let mut commit_tree = CommitTree::new();
    let it = vault_iter(path.as_ref())?;
    for record in it {
        let record = record?;
        commit_tree.insert(record.commit());
    }
    commit_tree.commit();
    Ok(commit_tree)
}
