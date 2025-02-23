//! Run integrity checks on event logs.
use crate::{Error, Result};
use async_stream::try_stream;
use binary_stream::futures::BinaryReader;
use futures::{
    pin_mut,
    stream::{BoxStream, Stream},
    StreamExt,
};
use sos_backend::{BackendTarget, FolderEventLog};
use sos_core::{
    commit::{CommitHash, CommitTree},
    encoding::encoding_options,
    events::{EventLog, EventRecord},
    AccountId, VaultId,
};
use sos_filesystem::formats::FileItem;
use sos_vfs as vfs;
use std::{io::SeekFrom, path::Path};
use tokio_stream::wrappers::ReceiverStream;

/// Integrity check for an event log comparing the precomputed
/// checksums with the encrypted content of each row.
pub async fn event_integrity2(
    target: &BackendTarget,
    account_id: &AccountId,
    folder_id: &VaultId,
) -> BoxStream<'static, Result<EventRecord>> {
    let (tx, rx) = tokio::sync::mpsc::channel(8);

    let target = target.clone();
    let account_id = *account_id;
    let folder_id = *folder_id;
    tokio::task::spawn(async move {
        let event_log =
            FolderEventLog::new_folder(target, &account_id, &folder_id)
                .await?;

        let stream = event_log.record_stream(false).await;
        pin_mut!(stream);

        while let Some(record) = stream.next().await {
            let record = record?;
            let commit = record.commit();
            let checksum = CommitHash(CommitTree::hash(record.event_bytes()));
            if &checksum == commit {
                tx.send(Ok(record)).await.unwrap();
            } else {
                tx.send(Err(Error::HashMismatch {
                    commit: *commit,
                    value: checksum,
                }))
                .await
                .unwrap();
            }
        }

        Ok::<_, Error>(())
    });

    ReceiverStream::new(rx).boxed()
}

/// Integrity check for an event log comparing the precomputed
/// checksums with the encrypted content of each row.
#[deprecated]
pub fn event_integrity(
    path: impl AsRef<Path>,
) -> impl Stream<Item = Result<Result<EventRecord>>> {
    try_stream! {
        let mut file = vfs::File::open(path.as_ref()).await?;
        let mut reader = BinaryReader::new(&mut file, encoding_options());

        let event_log = sos_filesystem::FolderEventLog::<Error>::new_folder(path.as_ref()).await?;
        let mut it = event_log.iter(false).await?;
        let mut last_checksum: Option<[u8; 32]> = None;

        while let Some(record) = it.next().await? {
            // Verify the row last commit matches the checksum
            // for the previous row
            if let Some(last_checksum) = last_checksum {
                let expected_last_commit = record.last_commit();
                if last_checksum != expected_last_commit {
                    yield Err(Error::HashMismatch {
                        commit: CommitHash(expected_last_commit),
                        value: CommitHash(last_checksum),
                    });
                }
            }

            // Verify the commit hash for the data
            let commit = record.commit();
            let value = record.value();
            let length = value.end - value.start;
            reader.seek(SeekFrom::Start(value.start)).await?;
            let buffer = reader.read_bytes(length as usize).await?;

            let checksum = CommitTree::hash(&buffer);
            if checksum != commit {
                yield Err(Error::HashMismatch {
                    commit: CommitHash(commit),
                    value: CommitHash(checksum),
                });
            }

            last_checksum = Some(record.commit());

            let record = record.into_event_record(buffer);
            yield Ok(record)
        }

    }
}
