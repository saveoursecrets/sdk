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
use async_stream::try_stream;
use binary_stream::futures::BinaryReader;
use futures::stream::Stream;
use std::{io::SeekFrom, path::Path};
use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

/// Integrity check for a vault file comparing the precomputed
/// checksums with the encrypted content of each row.
pub fn vault_integrity(
    path: impl AsRef<Path>,
) -> impl Stream<Item = Result<Result<VaultRecord>>> {
    try_stream! {
      FileIdentity::read_file(path.as_ref(), &VAULT_IDENTITY).await?;

      // Use an additional reader to read in the row values
      let mut file = vfs::File::open(path.as_ref()).await?.compat();
      let mut reader = BinaryReader::new(&mut file, encoding_options());

      let stream = vfs::File::open(path.as_ref()).await?.compat();
      let content_offset = Header::read_content_offset(path.as_ref()).await?;
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
          let value = record.value();
          let length = value.end - value.start;
          reader.seek(SeekFrom::Start(value.start)).await?;
          let buffer = reader.read_bytes(length as usize).await?;

          let checksum = CommitTree::hash(&buffer);
          if checksum != commit {
              yield Err(Error::VaultHashMismatch {
                  commit: hex::encode(commit),
                  value: hex::encode(checksum),
                  id: uuid::Uuid::from_slice(record.id().as_slice())?,
              });
          }
          yield Ok(record)
      }
    }
}
