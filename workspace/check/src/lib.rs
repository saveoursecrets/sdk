use std::path::PathBuf;
use uuid::Uuid;

mod error;

pub type Result<T> = std::result::Result<T, error::Error>;
pub use error::Error;

use sos_core::{
    commit_tree::{vault_commit_tree, wal_commit_tree},
    iter::vault_iter,
    vault::{Header, Vault},
    wal::WalItem,
};

/// Verify the integrity of a vault.
pub fn verify_vault(file: PathBuf, root: bool, commits: bool) -> Result<()> {
    if !file.is_file() {
        return Err(Error::NotFile(file));
    }
    let tree = vault_commit_tree(&file, true, |row_info| {
        if commits {
            println!("{}", hex::encode(&row_info.commit()));
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
    let tree = wal_commit_tree(&file, true, |row_info| {
        if commits {
            println!("{}", hex::encode(&row_info.commit()));
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
    let tree = Vault::build_tree(&vault)?;

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
