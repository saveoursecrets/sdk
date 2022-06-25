//! Functions to build commit trees and run integrity checks.
use std::path::Path;

use serde_binary::binary_rw::{BinaryReader, Endian, FileStream, OpenType};

use crate::{
    commit_tree::{hash, CommitTree, RowInfo, RowIterator},
    wal::file::{LogRow, WalFile},
    Error, Result,
};

/// Build a commit tree from a vault file optionally
/// verifying all the row checksums.
///
/// The `func` is invoked with the row information so
/// callers can display debugging information if necessary.
pub fn vault_commit_tree<P: AsRef<Path>, F>(
    vault: P,
    verify: bool,
    func: F,
) -> Result<CommitTree>
where
    F: Fn(&RowInfo) -> (),
{
    let mut tree = CommitTree::new();

    // Need an additional reader as we may also read in the
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
                return Err(Error::HashMismatch {
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

/// Build a commit tree from a WAL file optionally
/// verifying all the row checksums.
///
/// The `func` is invoked with the row information so
/// callers can display debugging information if necessary.
pub fn wal_commit_tree<P: AsRef<Path>, F>(
    vault: P,
    verify: bool,
    func: F,
) -> Result<CommitTree>
where
    F: Fn(&LogRow) -> (),
{
    let mut tree = CommitTree::new();

    // Need an additional reader as we may also read in the
    // values for the rows
    let mut value = FileStream::new(vault.as_ref(), OpenType::Open)?;
    let mut reader = BinaryReader::new(&mut value, Endian::Big);

    let wal = WalFile::new(vault.as_ref())?;

    for row_info in wal.iter()? {
        let row_info = row_info?;

        if verify {
            let value = row_info.read_value(&mut reader)?;
            let checksum = hash(&value);
            if checksum != row_info.commit {
                return Err(Error::HashMismatch {
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

#[cfg(test)]
mod test {
    use anyhow::Result;
    use std::io::Write;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::{
        test_utils::*,
        vault::{encode, VaultAccess},
    };

    // TODO: test for corrupt vault / WAL

    #[test]
    fn integrity_empty_vault() -> Result<()> {
        let (temp, _, _) = mock_vault_file()?;
        let commit_tree = vault_commit_tree(temp.path(), true, |_| {})?;
        assert!(commit_tree.root().is_none());
        Ok(())
    }

    #[test]
    fn integrity_vault() -> Result<()> {
        let (encryption_key, _) = mock_encryption_key()?;
        let (_, mut vault, _) = mock_vault_file()?;
        let secret_label = "Test note";
        let secret_note = "Super secret note for you to read.";
        let (secret_id, commit, _, _) = mock_vault_note(
            &mut vault,
            &encryption_key,
            secret_label,
            secret_note,
        )?;

        let buffer = encode(&vault)?;
        let mut temp = NamedTempFile::new()?;
        temp.write_all(&buffer)?;

        let commit_tree = vault_commit_tree(temp.path(), true, |_| {})?;
        assert!(commit_tree.root().is_some());
        Ok(())
    }
}
