use std::path::PathBuf;
use uuid::Uuid;

mod error;

pub type Result<T> = std::result::Result<T, error::Error>;
pub use error::Error;

use sos_core::{
    binary_rw::{BinaryReader, Endian, FileStream, OpenType},
    commit_tree::{hash, CommitTree, RowIterator},
};

/// Verify the integrity of a vault.
pub fn verify(vault: PathBuf, root: bool, commits: bool) -> Result<()> {
    if !vault.is_file() {
        return Err(Error::NotFile(vault));
    }

    let mut tree = CommitTree::new();
    let mut value = FileStream::new(&vault, OpenType::Open)?;
    let mut reader = BinaryReader::new(&mut value, Endian::Big);

    let mut stream = FileStream::new(&vault, OpenType::Open)?;
    let (mut iterator, _header) = RowIterator::new(&mut stream)?;
    for row_info in iterator {
        let row_info = row_info?;
        if commits {
            println!(
                "{}) {}",
                row_info.index + 1,
                hex::encode(&row_info.commit)
            );
        }
        let value = row_info.read_value(&mut reader)?;
        let checksum = hash(&value);
        if checksum != row_info.commit {
            return Err(Error::HashMismatch {
                index: row_info.index,
                total: row_info.total,
                commit: hex::encode(row_info.commit),
                value: hex::encode(checksum),
            });
        }

        tree.insert(row_info.into_commit());
    }

    tree.commit();

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
    let mut stream = FileStream::new(&vault, OpenType::Open)?;
    let (mut iterator, _header) = RowIterator::new(&mut stream)?;
    for row_info in iterator {
        let row_info = row_info?;
        let id = Uuid::from_bytes(row_info.into_id());
        println!("{}", id);
    }
    Ok(())
}
