//! Functions to build commit trees and run integrity checks.
use std::path::Path;

use serde_binary::binary_rw::{BinaryReader, Endian, FileStream, OpenType};

use crate::{
    commit_tree::{hash, CommitTree, RowInfo, RowIterator},
    Error, Result,
};

/// Build a commit tree from a vault file optionally
/// verifying all the row checksums.
///
/// The `func` is invoked with the row information so
/// callers can display debugging information if necessary.
pub fn vault_file_tree<P: AsRef<Path>, F>(
    vault: P,
    verify: bool,
    func: F,
) -> Result<CommitTree>
where
    F: Fn(&RowInfo) -> (),
{
    let mut tree = CommitTree::new();

    // Need an additional reader as we will also read in the
    // values for the rows
    let mut value = FileStream::new(&vault, OpenType::Open)?;
    let mut reader = BinaryReader::new(&mut value, Endian::Big);

    let mut stream = FileStream::new(&vault, OpenType::Open)?;
    let (iterator, _header) = RowIterator::new(&mut stream)?;
    for row_info in iterator {
        let row_info = row_info?;

        if verify {
            let value = row_info.read_value(&mut reader)?;
            let checksum = hash(&value);
            if checksum != row_info.commit {
                return Err(Error::VaultHashMismatch {
                    index: row_info.index,
                    total: row_info.total,
                    commit: hex::encode(row_info.commit),
                    value: hex::encode(checksum),
                });
            }
        }

        func(&row_info);
        tree.insert(row_info.into_commit());
    }

    tree.commit();
    Ok(tree)
}
