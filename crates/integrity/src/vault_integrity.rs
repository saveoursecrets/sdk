//! Run integrity checks on vault files.
use crate::{Error, Result};
use async_stream::try_stream;
use binary_stream::futures::BinaryReader;
use futures::{
    stream::{BoxStream, Stream},
    StreamExt,
};
use sos_backend::{
    database::{
        async_sqlite::rusqlite::Row,
        entity::{FolderEntity, SecretRow},
    },
    BackendTarget,
};
use sos_core::{
    commit::{CommitHash, CommitTree},
    constants::VAULT_IDENTITY,
    decode,
    encoding::encoding_options,
    AccountId, VaultCommit, VaultId,
};
use sos_filesystem::formats::{
    read_file_identity_bytes, FileItem, FormatStream, FormatStreamIterator,
    VaultRecord,
};
use sos_vault::Header;
use sos_vfs as vfs;
use std::{io::SeekFrom, path::Path};
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

/// Stream of vault commits.
async fn vault_stream(
    target: &BackendTarget,
    _account_id: &AccountId,
    folder_id: &VaultId,
) -> BoxStream<'static, Result<CommitHash>> {
    // let account_id = *account_id;
    let folder_id = *folder_id;
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    match target {
        BackendTarget::FileSystem(paths) => {
            let paths = paths.clone();
            tokio::task::spawn(async move {
                let path = paths.vault_path(&folder_id);
                read_file_identity_bytes(&path, &VAULT_IDENTITY).await?;

                // Use an additional reader to read in the row values
                let mut file = vfs::File::open(&path).await?;
                let mut reader =
                    BinaryReader::new(&mut file, encoding_options());

                let stream = vfs::File::open(&path).await?;
                let content_offset =
                    Header::read_content_offset(&path).await?;
                let mut it =
                    FormatStream::<VaultRecord, vfs::File>::new_file(
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
                    if checksum == commit {
                        tx.send(Ok(CommitHash(commit))).await.unwrap();
                    } else {
                        tx.send(Err(Error::VaultHashMismatch {
                            commit: CommitHash(commit),
                            value: CommitHash(checksum),
                            id: uuid::Uuid::from_slice(
                                record.id().as_slice(),
                            )?,
                        }))
                        .await
                        .unwrap();
                    }
                }

                Ok::<_, Error>(())
            });
        }
        BackendTarget::Database(paths, client) => {
            let client = client.clone();
            tokio::task::spawn(async move {
                client
                    .conn_and_then(move |conn| {
                        let folder_entity = FolderEntity::new(&conn);
                        let folder_row =
                            folder_entity.find_one(&folder_id)?;

                        let query = FolderEntity::find_all_secrets_query();

                        let mut stmt =
                            conn.prepare_cached(&query.as_string())?;

                        fn convert_row(row: &Row<'_>) -> Result<SecretRow> {
                            Ok(row.try_into()?)
                        }

                        let rows = stmt
                            .query_and_then([folder_row.row_id], |row| {
                                Ok::<_, Error>(convert_row(row)?)
                            })?;

                        /*
                        for row in rows {
                            let row = row?;
                            let sender = tx.clone();
                            futures::executor::block_on(async move {
                                if let Err(err) =
                                    sender.send(Ok(row.commit)).await
                                {
                                    tracing::error!(error = %err);
                                }
                            });
                        }
                        */

                        Ok::<_, Error>(())
                    })
                    .await?;

                Ok::<_, Error>(())
            });
        }
    }

    ReceiverStream::new(rx).boxed()
}

pub fn vault_integrity2(
    target: &BackendTarget,
    account_id: &AccountId,
    folder_id: &VaultId,
) -> Result<()> {
    todo!("new vault integrity");
}

/// Integrity check for a vault file comparing the precomputed
/// checksums with the encrypted content of each row.
#[deprecated]
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
                  commit: CommitHash(commit),
                  value: CommitHash(checksum),
                  id: uuid::Uuid::from_slice(record.id().as_slice())?,
              });
          }
          yield Ok(record)
      }
    }
}
