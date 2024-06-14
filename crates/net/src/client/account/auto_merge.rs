//! Implements auto merge logic for a remote.

use crate::{
    client::{RemoteBridge, Result, SyncClient},
    CommitDiffRequest, CommitScanRequest, EventPatchRequest,
};
use async_recursion::async_recursion;
use binary_stream::futures::{Decodable, Encodable};
use sos_sdk::{
    commit::{CommitHash, CommitProof, Comparison},
    events::{
        AccountEvent, EventLogExt, EventLogType, EventRecord, WriteEvent,
    },
    storage::StorageEventLogs,
    sync::{
        AccountDiff, FolderDiff, MaybeConflict, Merge, MergeOutcome, Patch,
        SyncPacket,
    },
    vault::VaultId,
};
use std::collections::HashSet;
use tracing::instrument;

const PROOF_SCAN_LIMIT: u16 = 32;

#[cfg(feature = "device")]
use sos_sdk::{events::DeviceEvent, sync::DeviceDiff};

#[cfg(feature = "files")]
use sos_sdk::{events::FileEvent, sync::FileDiff};

/// Whether to apply an auto merge to local or remote.
enum AutoMerge {
    /// Apply the events to the local event log.
    RewindLocal(Vec<EventRecord>),
    /// Push events to the remote.
    PushRemote(Vec<EventRecord>),
}

impl RemoteBridge {
    /// Try to auto merge on conflict.
    ///
    /// Searches the remote event log for a common ancestor and
    /// attempts to merge commits from the common ancestor with the
    /// diff that would have been applied.
    ///
    /// Once the changes have been merged a force update of the
    /// server is necessary.
    #[instrument(skip_all)]
    pub(crate) async fn auto_merge(
        &self,
        conflict: MaybeConflict,
        local: SyncPacket,
        _remote: SyncPacket,
    ) -> Result<()> {
        if conflict.identity {
            self.auto_merge_identity().await?;
        }

        if conflict.account {
            self.auto_merge_account().await?;
        }

        #[cfg(feature = "device")]
        if conflict.device {
            self.auto_merge_device().await?;
        }

        #[cfg(feature = "files")]
        if conflict.files {
            self.auto_merge_files().await?;
        }

        for (folder_id, _) in &conflict.folders {
            self.auto_merge_folder(&local, folder_id).await?;
        }

        Ok(())
    }

    async fn auto_merge_identity(&self) -> Result<()> {
        tracing::debug!("auto_merge::identity");

        let req = CommitScanRequest {
            log_type: EventLogType::Identity,
            offset: None,
            limit: PROOF_SCAN_LIMIT,
            ascending: false,
        };
        if let Some((ancestor_commit, proof)) = self.scan_proofs(req).await? {
            self.try_merge_from_ancestor::<WriteEvent>(
                EventLogType::Identity,
                ancestor_commit,
                proof,
            )
            .await?;
        }

        Ok(())
    }

    async fn auto_merge_account(&self) -> Result<()> {
        tracing::debug!("auto_merge::account");

        let req = CommitScanRequest {
            log_type: EventLogType::Account,
            offset: None,
            limit: PROOF_SCAN_LIMIT,
            ascending: false,
        };
        if let Some((ancestor_commit, proof)) = self.scan_proofs(req).await? {
            self.try_merge_from_ancestor::<AccountEvent>(
                EventLogType::Account,
                ancestor_commit,
                proof,
            )
            .await?;
        }

        Ok(())
    }

    #[cfg(feature = "device")]
    async fn auto_merge_device(&self) -> Result<()> {
        use sos_sdk::events::DeviceEvent;

        tracing::debug!("auto_merge::device");

        let req = CommitScanRequest {
            log_type: EventLogType::Device,
            offset: None,
            limit: PROOF_SCAN_LIMIT,
            ascending: false,
        };
        if let Some((ancestor_commit, proof)) = self.scan_proofs(req).await? {
            self.try_merge_from_ancestor::<DeviceEvent>(
                EventLogType::Device,
                ancestor_commit,
                proof,
            )
            .await?;
        }

        Ok(())
    }

    #[cfg(feature = "files")]
    async fn auto_merge_files(&self) -> Result<()> {
        use sos_sdk::events::FileEvent;

        tracing::debug!("auto_merge::files");

        let req = CommitScanRequest {
            log_type: EventLogType::Files,
            offset: None,
            limit: PROOF_SCAN_LIMIT,
            ascending: false,
        };
        if let Some((ancestor_commit, proof)) = self.scan_proofs(req).await? {
            self.try_merge_from_ancestor::<FileEvent>(
                EventLogType::Files,
                ancestor_commit,
                proof,
            )
            .await?;
        }

        Ok(())
    }

    async fn auto_merge_folder(
        &self,
        local: &SyncPacket,
        folder_id: &VaultId,
    ) -> Result<()> {
        tracing::debug!(folder_id = %folder_id, "auto_merge::folder");

        if local.status.folders.get(folder_id).is_some() {
            let req = CommitScanRequest {
                log_type: EventLogType::Folder(*folder_id),
                offset: None,
                limit: PROOF_SCAN_LIMIT,
                ascending: false,
            };
            if let Some((ancestor_commit, proof)) =
                self.scan_proofs(req).await?
            {
                self.try_merge_from_ancestor::<WriteEvent>(
                    EventLogType::Folder(*folder_id),
                    ancestor_commit,
                    proof,
                )
                .await?;
            }
        } else {
            tracing::warn!("local folder not found for auto_merge");
        }
        Ok(())
    }

    /// Try to merge from a shared ancestor commit.
    async fn try_merge_from_ancestor<T>(
        &self,
        log_type: EventLogType,
        commit: CommitHash,
        proof: CommitProof,
    ) -> Result<()>
    where
        T: Default + Encodable + Decodable + Send + Sync,
    {
        tracing::debug!(commit = %commit, "auto_merge::try_merge_from_ancestor");

        // Get the patch from local
        let local_patch = {
            let account = self.account.lock().await;
            match &log_type {
                EventLogType::Identity => {
                    let log = account.identity_log().await?;
                    let event_log = log.read().await;
                    event_log.diff_records(Some(&commit)).await?
                }
                EventLogType::Account => {
                    let log = account.account_log().await?;
                    let event_log = log.read().await;
                    event_log.diff_records(Some(&commit)).await?
                }
                #[cfg(feature = "device")]
                EventLogType::Device => {
                    let log = account.device_log().await?;
                    let event_log = log.read().await;
                    event_log.diff_records(Some(&commit)).await?
                }
                #[cfg(feature = "files")]
                EventLogType::Files => {
                    let log = account.file_log().await?;
                    let event_log = log.read().await;
                    event_log.diff_records(Some(&commit)).await?
                }
                EventLogType::Folder(id) => {
                    let log = account.folder_log(id).await?;
                    let event_log = log.read().await;
                    event_log.diff_records(Some(&commit)).await?
                }
                EventLogType::Noop => unreachable!(),
            }
        };

        // Fetch the patch of remote events
        let request = CommitDiffRequest {
            log_type,
            from_hash: commit,
        };
        let remote_patch = self.client.diff(&request).await?.patch;

        let result = self.merge_patches(local_patch, remote_patch).await?;

        match result {
            AutoMerge::RewindLocal(events) => {
                self.rewind_local(&log_type, commit, proof, events).await?;
            }
            AutoMerge::PushRemote(events) => {
                self.push_remote::<T>(&log_type, commit, proof, events)
                    .await?;
            }
        }

        Ok(())
    }

    async fn merge_patches(
        &self,
        mut local: Vec<EventRecord>,
        remote: Vec<EventRecord>,
    ) -> Result<AutoMerge> {
        tracing::info!(
            local_len = local.len(),
            remote_len = remote.len(),
            "auto_merge::merge_patches",
        );

        let local_commits =
            local.iter().map(|r| r.commit()).collect::<HashSet<_>>();
        let remote_commits =
            remote.iter().map(|r| r.commit()).collect::<HashSet<_>>();

        // If all the local commits exist in the remote
        // then apply the remote events to the local event
        // log.
        //
        // If we didn't do this then automerge could go on
        // ad infinitum.
        if local_commits.is_subset(&remote_commits) {
            return Ok(AutoMerge::RewindLocal(remote));
        }

        // Combine the event records
        local.extend(remote.into_iter());

        // Sort by time so the more recent changes will win (LWW)
        local.sort_by(|a, b| a.time().cmp(b.time()));

        Ok(AutoMerge::PushRemote(local))
    }

    /// Rewind a local event log and apply the events.
    async fn rewind_local(
        &self,
        log_type: &EventLogType,
        commit: CommitHash,
        proof: CommitProof,
        events: Vec<EventRecord>,
    ) -> Result<()> {
        tracing::debug!(
          log_type = ?log_type,
          commit = %commit,
          length = %events.len(),
          "auto_merge::rewind_local",
        );

        // Rewind the event log to the target commit
        self.rewind_event_log(log_type, &commit).await?;

        let mut outcome = MergeOutcome::default();

        // Merge the events after rewinding
        {
            let mut account = self.account.lock().await;
            match &log_type {
                EventLogType::Identity => {
                    let patch = Patch::<WriteEvent>::new(events).await?;
                    let diff = FolderDiff {
                        last_commit: Some(commit),
                        before: proof,
                        patch,
                        after: None,
                    };
                    account.merge_identity(&diff, &mut outcome).await?;
                }
                EventLogType::Account => {
                    let patch = Patch::<AccountEvent>::new(events).await?;
                    let diff = AccountDiff {
                        last_commit: Some(commit),
                        before: proof,
                        patch,
                        after: None,
                    };
                    account.merge_account(&diff, &mut outcome).await?;
                }
                #[cfg(feature = "device")]
                EventLogType::Device => {
                    let patch = Patch::<DeviceEvent>::new(events).await?;
                    let diff = DeviceDiff {
                        last_commit: Some(commit),
                        before: proof,
                        patch,
                        after: None,
                    };
                    account.merge_device(&diff, &mut outcome).await?;
                }
                #[cfg(feature = "files")]
                EventLogType::Files => {
                    let patch = Patch::<FileEvent>::new(events).await?;
                    let diff = FileDiff {
                        last_commit: Some(commit),
                        before: proof,
                        patch,
                        after: None,
                    };
                    account.merge_files(&diff, &mut outcome).await?;
                }
                EventLogType::Folder(id) => {
                    let patch = Patch::<WriteEvent>::new(events).await?;
                    let diff = FolderDiff {
                        last_commit: Some(commit),
                        before: proof,
                        patch,
                        after: None,
                    };
                    account.merge_folder(id, &diff, &mut outcome).await?;
                }
                EventLogType::Noop => unreachable!(),
            }
        }

        Ok(())
    }

    /// Push the events to a remote and rewind local.
    async fn push_remote<T>(
        &self,
        log_type: &EventLogType,
        commit: CommitHash,
        proof: CommitProof,
        events: Vec<EventRecord>,
    ) -> Result<()>
    where
        T: Default + Encodable + Decodable + Send + Sync,
    {
        tracing::debug!(
          log_type = ?log_type,
          commit = %commit,
          length = %events.len(),
          "auto_merge::push_remote",
        );

        let req = EventPatchRequest {
            log_type: *log_type,
            commit: Some(commit),
            proof,
            patch: events,
        };

        println!("patch_len {}", req.patch.len());

        todo!("push remote");
    }

    /// Rewind an event log to a specific commit.
    async fn rewind_event_log(
        &self,
        log_type: &EventLogType,
        commit: &CommitHash,
    ) -> Result<()> {
        tracing::debug!(
          log_type = ?log_type,
          commit = %commit,
          "automerge::rewind_event_log",
        );
        // Rewind the event log
        let account = self.account.lock().await;
        match &log_type {
            EventLogType::Identity => {
                let log = account.identity_log().await?;
                let mut event_log = log.write().await;
                event_log.rewind(commit).await?;
            }
            EventLogType::Account => {
                let log = account.account_log().await?;
                let mut event_log = log.write().await;
                event_log.rewind(commit).await?;
            }
            #[cfg(feature = "device")]
            EventLogType::Device => {
                let log = account.device_log().await?;
                let mut event_log = log.write().await;
                event_log.rewind(commit).await?;
            }
            #[cfg(feature = "files")]
            EventLogType::Files => {
                let log = account.file_log().await?;
                let mut event_log = log.write().await;
                event_log.rewind(commit).await?;
            }
            EventLogType::Folder(id) => {
                let log = account.folder_log(id).await?;
                let mut event_log = log.write().await;
                event_log.rewind(commit).await?;
            }
            EventLogType::Noop => unreachable!(),
        }
        Ok(())
    }

    /// Scan the remote for proofs that match this client.
    #[async_recursion]
    async fn scan_proofs(
        &self,
        request: CommitScanRequest,
    ) -> Result<Option<(CommitHash, CommitProof)>> {
        tracing::debug!(request = ?request, "auto_merge::scan_proofs");

        let response = self.client.scan(&request).await?;
        if !response.proofs.is_empty() {
            // Proofs are returned in the event log order
            // but we always want to scan from the end of
            // the event log so reverse the iteration
            for proof in response.proofs.iter().rev() {
                let commit_hashes =
                    self.compare_proof(&request.log_type, proof).await?;

                // Find the last matching commit from the indices
                // to prove
                if let Some(commit_hash) = commit_hashes.last() {
                    return Ok(Some((*commit_hash, proof.clone())));
                }
            }

            // Try to scan more proofs
            let mut req = request.clone();
            req.offset = Some(response.offset);
            self.scan_proofs(req).await
        } else {
            Ok(None)
        }
    }

    /// Determine if a local event log contains a proof
    /// received from the server.
    async fn compare_proof(
        &self,
        log_type: &EventLogType,
        proof: &CommitProof,
    ) -> Result<Vec<CommitHash>> {
        tracing::debug!(proof = ?proof, "auto_merge::compare_proof");

        let account = self.account.lock().await;
        let comparison = match &log_type {
            EventLogType::Identity => {
                let log = account.identity_log().await?;
                let event_log = log.read().await;
                event_log.tree().compare(proof)?
            }
            EventLogType::Account => {
                let log = account.account_log().await?;
                let event_log = log.read().await;
                event_log.tree().compare(proof)?
            }
            #[cfg(feature = "device")]
            EventLogType::Device => {
                let log = account.device_log().await?;
                let event_log = log.read().await;
                event_log.tree().compare(proof)?
            }
            #[cfg(feature = "files")]
            EventLogType::Files => {
                let log = account.file_log().await?;
                let event_log = log.read().await;
                event_log.tree().compare(proof)?
            }
            EventLogType::Folder(id) => {
                let log = account.folder_log(id).await?;
                let event_log = log.read().await;
                event_log.tree().compare(proof)?
            }
            EventLogType::Noop => unreachable!(),
        };

        tracing::debug!(
            comparison = ?comparison,
            "auto_merge::compare_proof",
        );

        if let Comparison::Contains(_, leaves) = comparison {
            let commits =
                leaves.into_iter().map(CommitHash).collect::<Vec<_>>();
            Ok(commits)
        } else {
            Ok(vec![])
        }
    }
}
