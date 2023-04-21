use std::path::{Path, PathBuf};
use uuid::Uuid;

use sos_core::{
    commit::{vault_commit_tree_file, wal_commit_tree_file, CommitTree},
    formats::vault_iter,
    hex, uuid,
    vault::Header,
    wal::WalItem,
};

use crate::{Error, Result};

pub mod cli;
pub use cli::run;

/// Verify the integrity of a vault.
pub fn verify_vault(file: PathBuf, root: bool, commits: bool) -> Result<()> {
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
pub fn verify_wal(file: PathBuf, root: bool, commits: bool) -> Result<()> {
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
pub fn status(vault: PathBuf) -> Result<()> {
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
