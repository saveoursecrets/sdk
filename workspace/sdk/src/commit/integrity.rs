//! Functions to build commit trees and run integrity checks.
use crate::{
    commit::CommitTree,
    formats::{vault_iter, EventLogFileRecord, FileItem, VaultRecord},
    vfs, Error, Result,
};
use binary_stream::{tokio::BinaryReader, Endian};

use crate::events::EventLogFile;

use std::path::Path;

/// Read the bytes for each entry into an owned buffer.
macro_rules! read_iterator_item {
    ($record:expr, $reader:expr) => {{
        let value = $record.value();
        let length = value.end - value.start;
        $reader.seek(value.start).await?;
        $reader.read_bytes(length as usize).await?
    }};
}

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
            let buffer = read_iterator_item!(&record, &mut reader);

            let checksum = CommitTree::hash(&buffer);
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

/// Build a commit tree from a event log file optionally
/// verifying all the row checksums.
///
/// The `func` is invoked with the row information so
/// callers can display debugging information if necessary.
pub async fn event_log_commit_tree_file<P: AsRef<Path>, F>(
    event_log_file: P,
    verify: bool,
    func: F,
) -> Result<CommitTree>
where
    F: Fn(&EventLogFileRecord),
{
    let mut tree = CommitTree::new();

    // Need an additional reader as we may also read in the
    // values for the rows
    let mut file = vfs::File::open(event_log_file.as_ref()).await?;
    let mut reader = BinaryReader::new(&mut file, Endian::Little);

    let event_log = EventLogFile::new(event_log_file.as_ref())?;
    let it = event_log.iter()?;
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
            let commit = record.commit();
            let buffer = read_iterator_item!(&record, &mut reader);

            let checksum = CommitTree::hash(&buffer);
            if checksum != commit {
                return Err(Error::HashMismatch {
                    commit: hex::encode(commit),
                    value: hex::encode(checksum),
                });
            }

            let buffer = event_log.read_buffer(&record)?;
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

    // TODO: test for corrupt vault / event log

    #[tokio::test]
    async fn integrity_empty_vault() -> Result<()> {
        let (temp, _, _) = mock_vault_file()?;
        let commit_tree =
            vault_commit_tree_file(temp.path(), true, |_| {}).await?;
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

        let commit_tree =
            vault_commit_tree_file(temp.path(), true, |_| {}).await?;
        assert!(commit_tree.root().is_some());
        Ok(())
    }

    #[tokio::test]
    async fn integrity_event_log() -> Result<()> {
        let (temp, _, _, _) = mock_event_log_file()?;
        let commit_tree =
            event_log_commit_tree_file(temp.path(), true, |_| {}).await?;
        assert!(commit_tree.root().is_some());
        Ok(())
    }
}
