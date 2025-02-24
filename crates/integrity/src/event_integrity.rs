//! Run integrity checks on event logs.
use crate::{Error, Result};
use futures::{pin_mut, stream::BoxStream, StreamExt};
use sos_backend::{BackendTarget, FolderEventLog};
use sos_core::{
    commit::{CommitHash, CommitTree},
    events::{EventLog, EventRecord},
    AccountId, VaultId,
};
use tokio_stream::wrappers::ReceiverStream;

/// Integrity check for an event log comparing the precomputed
/// checksums with the encrypted content of each row.
pub fn event_integrity(
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
                if let Err(err) = tx.send(Ok(record)).await {
                    tracing::error!(error = %err);
                }
            } else {
                if let Err(err) = tx
                    .send(Err(Error::HashMismatch {
                        commit: *commit,
                        value: checksum,
                    }))
                    .await
                {
                    tracing::error!(error = %err);
                }
            }
        }

        Ok::<_, Error>(())
    });

    ReceiverStream::new(rx).boxed()
}
