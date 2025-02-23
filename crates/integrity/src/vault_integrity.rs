//! Run integrity checks on vault files.
use crate::{Error, Result};
use async_stream::try_stream;
use binary_stream::futures::BinaryReader;
use futures::stream::Stream;
use sos_backend::BackendTarget;
use sos_core::commit::CommitTree;
use sos_core::{constants::VAULT_IDENTITY, encoding::encoding_options};
use sos_filesystem::formats::{
    read_file_identity_bytes, FileItem, FormatStream, FormatStreamIterator,
    VaultRecord,
};
use sos_vault::Header;
use sos_vfs as vfs;
use std::{io::SeekFrom, path::Path};

pub fn vault_integrity2(target: &BackendTarget) -> Result<()> {
    todo!("new vault integrity");
}

/// Integrity check for a vault file comparing the precomputed
/// checksums with the encrypted content of each row.
pub fn vault_integrity(
    path: impl AsRef<Path>,
) -> impl Stream<Item = Result<Result<VaultRecord>>> {
    try_stream! {
      read_file_identity_bytes(path.as_ref(), &VAULT_IDENTITY).await?;

      // Use an additional reader to read in the row values
      let mut file = vfs::File::open(path.as_ref()).await?;
      let mut reader = BinaryReader::new(&mut file, encoding_options());

      let stream = vfs::File::open(path.as_ref()).await?;
      let content_offset = Header::read_content_offset(path.as_ref()).await?;
      let mut it = FormatStream::<VaultRecord, vfs::File>::new_file(
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
