//! Run integrity checks on vault files.
use crate::{Error, Result};
use binary_stream::futures::BinaryReader;
use futures::{stream::BoxStream, StreamExt, TryStreamExt};
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
    encoding::encoding_options,
    AccountId, SecretId, VaultId,
};
use sos_filesystem::formats::{
    read_file_identity_bytes, FileItem, FormatStream, FormatStreamIterator,
    VaultRecord,
};
use sos_vault::Header;
use sos_vfs as vfs;
use std::io::SeekFrom;
use tokio_stream::wrappers::ReceiverStream;

/// Stream of vault commits.
fn vault_stream(
    target: BackendTarget,
    account_id: &AccountId,
    folder_id: &VaultId,
) -> BoxStream<'static, Result<(SecretId, CommitHash, Vec<u8>)>> {
    let folder_id = *folder_id;
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let target = target.with_account_id(account_id);
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
                    let id = SecretId::from_slice(record.id().as_slice())?;
                    tx.send(Ok((id, CommitHash(commit), buffer)))
                        .await
                        .unwrap();
                }

                Ok::<_, Error>(())
            });
        }
        BackendTarget::Database(_, client) => {
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
                            .query_and_then([folder_row.row_id], convert_row)?;

                        for row in rows {
                            let row = row?;

                            let id: SecretId = row.identifier().parse()?;
                            let commit = CommitHash(row.commit().try_into()?);
                            let meta_bytes = row.meta_bytes();
                            let secret_bytes = row.meta_bytes();
                            let mut buffer = Vec::with_capacity(
                                meta_bytes.len() + secret_bytes.len(),
                            );
                            buffer.extend_from_slice(meta_bytes);
                            buffer.extend_from_slice(secret_bytes);

                            let sender = tx.clone();
                            futures::executor::block_on(async move {
                                if let Err(err) = sender
                                    .send(Ok((id, commit, buffer)))
                                    .await
                                {
                                    tracing::error!(error = %err);
                                }
                            });
                        }

                        Ok::<_, Error>(())
                    })
                    .await?;

                Ok::<_, Error>(())
            });
        }
    }

    ReceiverStream::new(rx).boxed()
}

/// Integrity check for a vault file comparing the precomputed
/// checksums with the encrypted content of each row.
pub fn vault_integrity(
    target: &BackendTarget,
    account_id: &AccountId,
    folder_id: &VaultId,
) -> BoxStream<'static, Result<(SecretId, CommitHash)>> {
    let stream = vault_stream(target.clone(), account_id, folder_id);
    stream
        .try_filter_map(|(id, expected_checksum, buffer)| async move {
            let checksum = CommitTree::hash(&buffer);
            if &checksum == expected_checksum.as_ref() {
                Ok(Some((id, expected_checksum)))
            } else {
                Err(Error::VaultHashMismatch {
                    commit: expected_checksum,
                    value: CommitHash(checksum),
                    id,
                })
            }
        })
        .boxed()
}
