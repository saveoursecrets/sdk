//! Run integrity checks on vault files.
use crate::{
    commit::CommitTree,
    constants::VAULT_IDENTITY,
    encoding::encoding_options,
    formats::{FileIdentity, FileItem, VaultRecord},
    formats::{FormatStream, FormatStreamIterator},
    vault::Header,
    vfs, Error, Result,
};
use binary_stream::futures::BinaryReader;
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
    func: F,
) -> Result<()>
where
    F: Fn(&VaultRecord),
{
    FileIdentity::read_file(vault.as_ref(), &VAULT_IDENTITY).await?;

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

        func(&record);
    }

    Ok(())
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
        let (temp, _) = mock_vault_file().await?;
        vault_commit_tree_file(temp.path(), |_| {}).await?;
        Ok(())
    }

    #[tokio::test]
    async fn integrity_vault() -> Result<()> {
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (_, mut vault) = mock_vault_file().await?;
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

        vault_commit_tree_file(temp.path(), |_| {}).await?;
        Ok(())
    }
}
