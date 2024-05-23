//! Functions to build commit trees and run integrity checks.
use crate::events::{EventLogExt, FolderEventLog};
use crate::{
    commit::CommitTree,
    constants::VAULT_IDENTITY,
    encoding::encoding_options,
    formats::{EventLogRecord, FileItem, VaultRecord},
    formats::{FileIdentity, FormatStream, FormatStreamIterator},
    vault::Header,
    vfs, Error, Result,
};
use binary_stream::futures::BinaryReader;
use core::slice::SlicePattern;
use std::io::SeekFrom;
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

use std::path::Path;

/// Read the bytes for each entry into an owned buffer.
macro_rules! read_iterator_item {
    ($record:expr, $reader:expr) => {{
        let value = $record.value();
        let length = value.end - value.start;
        $reader.seek(SeekFrom::Start(value.start)).await?;
        $reader.read_bytes(length as usize).await?
    }};
}

/// Build a commit tree from a vault file optionally
/// verifying all the row checksums.
///
/// The `func` is invoked with the row information so
/// callers can display debugging information if necessary.
pub async fn vault_commit_tree_file<F>(
    vault: impl AsRef<Path>,
    verify: bool,
    func: F,
) -> Result<CommitTree>
where
    F: Fn(&VaultRecord),
{
    FileIdentity::read_file(vault.as_ref(), &VAULT_IDENTITY).await?;

    let mut tree = CommitTree::new();
    // Need an additional reader as we may also read in the
    // values for the rows
    let mut file = vfs::File::open(vault.as_ref()).await?.compat();
    let mut reader = BinaryReader::new(&mut file, encoding_options());

    let stream = vfs::File::open(vault.as_ref()).await?.compat();
    let content_offset = Header::read_content_offset(vault.as_ref()).await?;
    let mut it = FormatStream::<VaultRecord, Compat<vfs::File>>::new_file(
        stream,
        &VAULT_IDENTITY,
        true,
        Some(content_offset),
        false,
    )
    .await?;

    while let Some(record) = it.next().await? {
        if verify {
            let commit = record.commit();
            let buffer = read_iterator_item!(&record, &mut reader);
            let checksum = CommitTree::hash(&buffer);
            if checksum != commit {
                return Err(Error::VaultHashMismatch {
                    commit: hex::encode(commit),
                    value: hex::encode(checksum),
                    id: uuid::Uuid::from_slice(record.id().as_slice())?,
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
pub async fn event_log_commit_tree_file<F>(
    event_log_file: impl AsRef<Path>,
    verify: bool,
    func: F,
) -> Result<CommitTree>
where
    F: Fn(&EventLogRecord),
{
    let mut tree = CommitTree::new();

    // Need an additional reader as we may also read in the
    // values for the rows
    let mut file = vfs::File::open(event_log_file.as_ref()).await?.compat();
    let mut reader = BinaryReader::new(&mut file, encoding_options());

    let event_log = FolderEventLog::new(event_log_file.as_ref()).await?;
    let mut it = event_log.iter(false).await?;
    let mut last_checksum: Option<[u8; 32]> = None;

    while let Some(record) = it.next().await? {
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

            last_checksum = Some(record.commit());
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
        let (temp, _, _) = mock_vault_file().await?;
        let commit_tree =
            vault_commit_tree_file(temp.path(), true, |_| {}).await?;
        assert!(commit_tree.root().is_none());
        Ok(())
    }

    #[tokio::test]
    async fn integrity_vault() -> Result<()> {
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (_, mut vault, _) = mock_vault_file().await?;
        let secret_label = "Test note";
        let secret_note = "Super secret note for you to read.";
        let (_secret_id, _commit, _, _, _) = mock_vault_note(
            &mut vault,
            &encryption_key,
            secret_label,
            secret_note,
        )
        .await?;

        let buffer = encode(&vault).await?;
        let mut temp = NamedTempFile::new()?;
        temp.write_all(&buffer)?;

        let commit_tree =
            vault_commit_tree_file(temp.path(), true, |_| {}).await?;
        assert!(commit_tree.root().is_some());
        Ok(())
    }

    #[tokio::test]
    async fn integrity_event_log() -> Result<()> {
        let (temp, _, _, _) = mock_event_log_file().await?;
        let commit_tree =
            event_log_commit_tree_file(temp.path(), true, |_| {}).await?;
        assert!(commit_tree.root().is_some());
        Ok(())
    }
}
