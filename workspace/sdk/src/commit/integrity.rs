//! Functions to build commit trees and run integrity checks.
use crate::{
    commit::CommitTree,
    formats::{vault_iter, FileItem, VaultRecord, WalFileRecord},
    wal::{WalItem, WalProvider},
    vfs,
    Error, Result,
};
use binary_stream::{tokio::BinaryReader, Endian};

use crate::wal::file::WalFile;

use std::path::Path;

/// Build a commit tree from a vault file optionally
/// verifying all the row checksums.
///
/// The `func` is invoked with the row information so
/// callers can display debugging information if necessary.
pub async fn vault_commit_tree_file<P: AsRef<Path>, F>(
    vault: P,
    verify: bool,
    func: F,
) -> Result<CommitTree>
where
    F: Fn(&VaultRecord),
{
    let mut tree = CommitTree::new();
    // Need an additional reader as we may also read in the
    // values for the rows
    let mut file = vfs::File::open(vault.as_ref()).await?;
    let mut reader = BinaryReader::new(&mut file, Endian::Little);
    let it = vault_iter(vault.as_ref())?;

    for record in it {
        let record = record?;

        if verify {
            let commit = record.commit();
            let value = record.read_bytes(&mut reader)?;

            let checksum = CommitTree::hash(&value);
            if checksum != commit {
                return Err(Error::HashMismatch {
                    commit: hex::encode(commit),
                    value: hex::encode(checksum),
                });
            }
        }

        func(&record);
        tree.insert(record.commit());
    }

    tree.commit();
    Ok(tree)
}

/// Build a commit tree from a WAL file optionally
/// verifying all the row checksums.
///
/// The `func` is invoked with the row information so
/// callers can display debugging information if necessary.
pub async fn wal_commit_tree_file<P: AsRef<Path>, F>(
    wal_file: P,
    verify: bool,
    func: F,
) -> Result<CommitTree>
where
    F: Fn(&WalFileRecord),
{
    let mut tree = CommitTree::new();

    // Need an additional reader as we may also read in the
    // values for the rows
    let mut file = vfs::File::open(wal_file.as_ref()).await?;
    let mut reader = BinaryReader::new(&mut file, Endian::Little);

    let wal = WalFile::new(wal_file.as_ref())?;
    let it = wal.iter()?;
    let mut last_checksum: Option<[u8; 32]> = None;

    for record in it {
        let record = record?;

        if verify {
            // Verify the row last commit matches the checksum
            // for the previous row
            if let Some(last_checksum) = last_checksum {
                let expected_last_commit = record.last_commit();
                if last_checksum != expected_last_commit {
                    return Err(Error::HashMismatch {
                        commit: hex::encode(expected_last_commit),
                        value: hex::encode(last_checksum),
                    });
                }
            }

            // Verify the commit hash for the data
            let value = record.read_bytes(&mut reader)?;

            let checksum = CommitTree::hash(&value);
            if checksum != record.commit() {
                return Err(Error::HashMismatch {
                    commit: hex::encode(record.commit()),
                    value: hex::encode(checksum),
                });
            }

            let buffer = wal.read_buffer(&record)?;
            last_checksum = Some(CommitTree::hash(&buffer));
        }

        func(&record);
        tree.insert(record.commit());
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
    use crate::{encode, test_utils::*};

    // TODO: test for corrupt vault / WAL

    #[tokio::test]
    async fn integrity_empty_vault() -> Result<()> {
        let (temp, _, _) = mock_vault_file()?;
        let commit_tree = vault_commit_tree_file(temp.path(), true, |_| {}).await?;
        assert!(commit_tree.root().is_none());
        Ok(())
    }

    #[tokio::test]
    async fn integrity_vault() -> Result<()> {
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (_, mut vault, _) = mock_vault_file()?;
        let secret_label = "Test note";
        let secret_note = "Super secret note for you to read.";
        let (_secret_id, _commit, _, _, _) = mock_vault_note(
            &mut vault,
            &encryption_key,
            secret_label,
            secret_note,
        )?;

        let buffer = encode(&vault)?;
        let mut temp = NamedTempFile::new()?;
        temp.write_all(&buffer)?;

        let commit_tree = vault_commit_tree_file(temp.path(), true, |_| {}).await?;
        assert!(commit_tree.root().is_some());
        Ok(())
    }

    #[tokio::test]
    async fn integrity_wal() -> Result<()> {
        let (temp, _, _, _) = mock_wal_file()?;
        let commit_tree = wal_commit_tree_file(temp.path(), true, |_| {}).await?;
        assert!(commit_tree.root().is_some());
        Ok(())
    }
}
