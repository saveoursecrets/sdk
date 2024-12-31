//! Helper functions for server implementations.
use crate::{
    error::MergeError, DiffRequest, DiffResponse, EventLogType, Merge,
    MergeOutcome, PatchRequest, PatchResponse, Result, ScanRequest,
    ScanResponse, SyncPacket, SyncStorage,
};
use binary_stream::futures::{Decodable, Encodable};
use sos_sdk::{
    events::{
        AccountDiff, AccountEvent, CheckedPatch, DeviceDiff, DeviceEvent,
        DiscEventLog, EventRecord, FolderDiff, Patch, WriteEvent,
    },
    prelude::EventLogExt,
};

use sos_database::StorageEventLogs;

#[cfg(feature = "files")]
use sos_sdk::events::{FileDiff, FileEvent};

/// Sync an account.
pub async fn sync_account<S, E>(
    packet: SyncPacket,
    storage: &mut S,
) -> std::result::Result<(SyncPacket, MergeOutcome), E>
where
    S: SyncStorage + Merge + Send + Sync + 'static,
    E: std::error::Error
        + std::fmt::Debug
        + From<<S as StorageEventLogs>::Error>
        + From<MergeError<S>>
        + From<sos_core::Error>
        + From<sos_sdk::Error>
        + From<sos_database::Error>
        + From<crate::Error>
        + Send
        + Sync
        + 'static,
{
    let (remote_status, mut diff) = (packet.status, packet.diff);

    // Apply the diff to the storage
    let mut outcome = MergeOutcome::default();
    let compare = {
        tracing::debug!("merge_server");

        // Only try to merge folders that exist in storage
        // otherwise after folder deletion sync will fail
        let folders = storage
            .folder_details()
            .await?
            .into_iter()
            .map(|s| *s.id())
            .collect::<Vec<_>>();
        diff.folders.retain(|k, _| folders.contains(k));

        storage
            .merge(diff, &mut outcome)
            .await
            .map_err(MergeError::<S>::new)?
    };

    // Generate a new diff so the client can apply changes
    // that exist in remote but not in the local
    let (local_status, diff) = {
        // let reader = account.read().await;
        let (_, local_status, diff) =
            crate::diff::<_, E>(storage, remote_status).await?;
        (local_status, diff)
    };

    let packet = SyncPacket {
        status: local_status,
        diff,
        compare: Some(compare),
    };

    Ok((packet, outcome))
}

/// Read a diff of events from a event log.
pub async fn event_diff<S, E>(
    req: &DiffRequest,
    storage: &S,
) -> std::result::Result<DiffResponse, E>
where
    S: StorageEventLogs + Send + Sync + 'static,
    E: From<<S as StorageEventLogs>::Error>
        + From<sos_sdk::Error>
        + From<sos_core::Error>
        + Send
        + Sync
        + 'static,
{
    match &req.log_type {
        EventLogType::Identity => {
            let log = storage.identity_log().await?;
            let event_log = log.read().await;
            diff_log(&req, &*event_log).await
        }
        EventLogType::Account => {
            let log = storage.account_log().await?;
            let event_log = log.read().await;
            diff_log(&req, &*event_log).await
        }
        EventLogType::Device => {
            let log = storage.device_log().await?;
            let event_log = log.read().await;
            diff_log(&req, &*event_log).await
        }
        #[cfg(feature = "files")]
        EventLogType::Files => {
            let log = storage.file_log().await?;
            let event_log = log.read().await;
            diff_log(&req, &*event_log).await
        }
        EventLogType::Folder(id) => {
            let log = storage.folder_log(id).await?;
            let event_log = log.read().await;
            diff_log(&req, &*event_log).await
        }
    }
}

/// Create a diff response from a request and target event log.
async fn diff_log<T, E>(
    req: &DiffRequest,
    event_log: &DiscEventLog<T>,
) -> std::result::Result<DiffResponse, E>
where
    T: Default + Encodable + Decodable + Send + Sync + 'static,
    E: From<sos_sdk::Error> + From<sos_core::Error> + Send + Sync + 'static,
{
    Ok(DiffResponse {
        patch: event_log.diff_records(req.from_hash.as_ref()).await?,
        checkpoint: event_log.tree().head()?,
    })
}

/// Scan event proofs.
pub async fn event_scan<S, E>(
    req: &ScanRequest,
    storage: &S,
) -> std::result::Result<ScanResponse, E>
where
    S: StorageEventLogs,
    E: From<<S as StorageEventLogs>::Error>
        + From<crate::Error>
        + Send
        + Sync
        + 'static,
{
    let response = match &req.log_type {
        EventLogType::Identity => {
            let log = storage.identity_log().await?;
            let event_log = log.read().await;
            scan_log(&req, &*event_log).await?
        }
        EventLogType::Account => {
            let log = storage.account_log().await?;
            let event_log = log.read().await;
            scan_log(&req, &*event_log).await?
        }
        EventLogType::Device => {
            let log = storage.device_log().await?;
            let event_log = log.read().await;
            scan_log(&req, &*event_log).await?
        }
        #[cfg(feature = "files")]
        EventLogType::Files => {
            let log = storage.file_log().await?;
            let event_log = log.read().await;
            scan_log(&req, &*event_log).await?
        }
        EventLogType::Folder(id) => {
            let log = storage.folder_log(&id).await?;
            let event_log = log.read().await;
            scan_log(&req, &*event_log).await?
        }
    };

    Ok(response)
}

/// Scan an event log.
async fn scan_log<T>(
    req: &ScanRequest,
    event_log: &DiscEventLog<T>,
) -> Result<ScanResponse>
where
    T: Default + Encodable + Decodable + Send + Sync + 'static,
{
    let mut res = ScanResponse {
        first_proof: None,
        proofs: vec![],
        offset: 0,
    };
    let offset = req.offset;
    let num_commits = event_log.tree().len() as u64;

    let mut index = if event_log.tree().len() > 0 {
        event_log.tree().len() - 1
    } else {
        0
    };

    if event_log.tree().len() > 0 {
        res.first_proof = Some(event_log.tree().proof(&[0])?);
    }

    // Short circuit if the offset is clearly out of bounds
    if offset >= num_commits {
        res.offset = num_commits;
        return Ok(res);
    }

    let mut it = event_log.iter(true).await?;
    let mut skip = 0;

    loop {
        let event = it.next().await?;
        if offset > 0 && skip < offset {
            if index > 0 {
                index -= 1;
            }
            skip += 1;
            continue;
        }
        if let Some(_event) = event {
            let proof = event_log.tree().proof(&[index])?;
            res.proofs.insert(0, proof);
            res.offset = offset + res.proofs.len() as u64;

            if index > 0 {
                index -= 1;
            }

            if res.proofs.len() == req.limit as usize {
                break;
            }
        } else {
            break;
        }
    }
    Ok(res)
}

/// Apply a patch of events rewinding to an optional checkpoint commit
/// before applying the patch.
pub async fn event_patch<S, E>(
    req: PatchRequest,
    storage: &mut S,
) -> std::result::Result<(PatchResponse, MergeOutcome), E>
where
    S: StorageEventLogs + Merge,
    E: std::error::Error
        + std::fmt::Debug
        + From<<S as StorageEventLogs>::Error>
        + From<MergeError<S>>
        + From<sos_sdk::Error>
        + Send
        + Sync
        + 'static,
{
    let (checked_patch, outcome, records) = match &req.log_type {
        EventLogType::Identity => {
            let patch = Patch::<WriteEvent>::new(req.patch);
            let (last_commit, records) = if let Some(commit) = &req.commit {
                let log = storage.identity_log().await?;
                let mut event_log = log.write().await;
                let records = event_log.rewind(commit).await?;
                (Some(*commit), records)
            } else {
                (None, vec![])
            };

            let diff = FolderDiff {
                last_commit,
                checkpoint: req.proof,
                patch,
            };

            let mut outcome = MergeOutcome::default();
            (
                storage
                    .merge_identity(diff, &mut outcome)
                    .await
                    .map_err(MergeError::<S>::new)?,
                outcome,
                records,
            )
        }
        EventLogType::Account => {
            let patch = Patch::<AccountEvent>::new(req.patch);
            let (last_commit, records) = if let Some(commit) = &req.commit {
                let log = storage.account_log().await?;
                let mut event_log = log.write().await;
                let records = event_log.rewind(commit).await?;
                (Some(*commit), records)
            } else {
                (None, vec![])
            };

            let diff = AccountDiff {
                last_commit,
                checkpoint: req.proof,
                patch,
            };

            let mut outcome = MergeOutcome::default();
            (
                storage
                    .merge_account(diff, &mut outcome)
                    .await
                    .map_err(MergeError::<S>::new)?
                    .0,
                outcome,
                records,
            )
        }
        EventLogType::Device => {
            let patch = Patch::<DeviceEvent>::new(req.patch);
            let (last_commit, records) = if let Some(commit) = &req.commit {
                let log = storage.device_log().await?;
                let mut event_log = log.write().await;
                let records = event_log.rewind(commit).await?;
                (Some(*commit), records)
            } else {
                (None, vec![])
            };

            let diff = DeviceDiff {
                last_commit,
                checkpoint: req.proof,
                patch,
            };

            let mut outcome = MergeOutcome::default();
            (
                storage
                    .merge_device(diff, &mut outcome)
                    .await
                    .map_err(MergeError::<S>::new)?,
                outcome,
                records,
            )
        }
        #[cfg(feature = "files")]
        EventLogType::Files => {
            let patch = Patch::<FileEvent>::new(req.patch);
            let (last_commit, records) = if let Some(commit) = &req.commit {
                let log = storage.file_log().await?;
                let mut event_log = log.write().await;
                let records = event_log.rewind(commit).await?;
                (Some(*commit), records)
            } else {
                (None, vec![])
            };

            let diff = FileDiff {
                last_commit,
                checkpoint: req.proof,
                patch,
            };

            let mut outcome = MergeOutcome::default();
            (
                storage
                    .merge_files(diff, &mut outcome)
                    .await
                    .map_err(MergeError::<S>::new)?,
                outcome,
                records,
            )
        }
        EventLogType::Folder(id) => {
            let patch = Patch::<WriteEvent>::new(req.patch);
            let (last_commit, records) = if let Some(commit) = &req.commit {
                let log = storage.folder_log(&id).await?;
                let mut event_log = log.write().await;
                let records = event_log.rewind(commit).await?;
                (Some(*commit), records)
            } else {
                (None, vec![])
            };

            let diff = FolderDiff {
                last_commit,
                checkpoint: req.proof,
                patch,
            };

            let mut outcome = MergeOutcome::default();
            (
                storage
                    .merge_folder(&id, diff, &mut outcome)
                    .await
                    .map_err(MergeError::<S>::new)?
                    .0,
                outcome,
                records,
            )
        }
    };

    // Rollback the rewind if the merge failed
    if let CheckedPatch::Conflict { head, .. } = &checked_patch {
        tracing::warn!(
            head = ?head,
            num_records = ?records.len(),
            "events_patch::rollback_rewind");
        rollback_rewind::<_, E>(&req.log_type, storage, records).await?;
    }

    Ok((PatchResponse { checked_patch }, outcome))
}

async fn rollback_rewind<S, E>(
    log_type: &EventLogType,
    storage: &mut S,
    records: Vec<EventRecord>,
) -> std::result::Result<(), E>
where
    S: StorageEventLogs,
    E: std::error::Error
        + std::fmt::Debug
        + From<<S as StorageEventLogs>::Error>
        + From<sos_sdk::Error>
        + Send
        + Sync
        + 'static,
{
    match log_type {
        EventLogType::Identity => {
            let log = storage.identity_log().await?;
            let mut event_log = log.write().await;
            event_log.apply_records(records).await?;
        }
        EventLogType::Account => {
            let log = storage.account_log().await?;
            let mut event_log = log.write().await;
            event_log.apply_records(records).await?;
        }
        EventLogType::Device => {
            let log = storage.device_log().await?;
            let mut event_log = log.write().await;
            event_log.apply_records(records).await?;
        }
        #[cfg(feature = "files")]
        EventLogType::Files => {
            let log = storage.file_log().await?;
            let mut event_log = log.write().await;
            event_log.apply_records(records).await?;
        }
        EventLogType::Folder(id) => {
            let log = storage.folder_log(id).await?;
            let mut event_log = log.write().await;
            event_log.apply_records(records).await?;
        }
    }

    Ok(())
}
