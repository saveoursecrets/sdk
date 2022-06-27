use std::path::PathBuf;
use uuid::Uuid;

mod error;

pub type Result<T> = std::result::Result<T, error::Error>;
pub use error::Error;

use sos_core::{
    binary_rw::{FileStream, OpenType},
    commit_tree::{
        integrity::{vault_commit_tree, wal_commit_tree},
        CommitTree, RowIterator,
    },
    wal::WalItem,
};

/// Verify the integrity of a vault.
pub fn verify_vault(file: PathBuf, root: bool, commits: bool) -> Result<()> {
    if !file.is_file() {
        return Err(Error::NotFile(file));
    }
    let tree = vault_commit_tree(&file, true, |row_info| {
        if commits {
            println!("{}", hex::encode(&row_info.commit));
        }
    })?;
    if root {
        if let Some(root) = tree.root() {
            println!("{}", hex::encode(root));
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
    let tree = wal_commit_tree(&file, true, |row_info| {
        if commits {
            println!("{}", hex::encode(&row_info.commit()));
        }
    })?;
    if root {
        if let Some(root) = tree.root() {
            println!("{}", hex::encode(root));
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

    let mut stream = FileStream::new(&vault, OpenType::Open)?;
    let (mut iterator, header) = RowIterator::new(&mut stream)?;
    let total = *iterator.total_rows();
    let tree = CommitTree::from_iterator(&mut iterator)?;

    println!("{}", header);
    println!("Rows: {}", total);
    if let Some(root) = tree.root() {
        println!("Commit: {}", hex::encode(root));
    }
    Ok(())
}

/// Print the vault keys.
pub fn keys(vault: PathBuf) -> Result<()> {
    if !vault.is_file() {
        return Err(Error::NotFile(vault));
    }

    let mut stream = FileStream::new(&vault, OpenType::Open)?;
    let (iterator, _header) = RowIterator::new(&mut stream)?;
    for row_info in iterator {
        let row_info = row_info?;
        let id = Uuid::from_bytes(*row_info.id());
        println!("{}", id);
    }
    Ok(())
}
