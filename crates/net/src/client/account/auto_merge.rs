//! Implements auto merge logic for a remote.

use crate::{
    client::{Error, RemoteBridge, Result, SyncClient},
    CommitDiffRequest, CommitScanRequest, EventPatchRequest,
};
use async_recursion::async_recursion;
use binary_stream::futures::{Decodable, Encodable};
use sos_sdk::{
    account::Account,
    commit::{CommitHash, CommitProof, CommitTree},
    events::{
        AccountEvent, EventLogExt, EventLogType, EventRecord, WriteEvent,
    },
    storage::StorageEventLogs,
    sync::{
        AccountDiff, CheckedPatch, FolderDiff, ForceMerge,
        HardConflictResolver, MaybeConflict, Merge, MergeOutcome, Patch,
        SyncOptions, SyncStatus,
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
        options: &SyncOptions,
        conflict: MaybeConflict,
        local: SyncStatus,
        _remote: SyncStatus,
    ) -> Result<()> {
        let mut force_merge_outcome = MergeOutcome::default();
        let mut has_hard_conflict = false;

        // println!("running auto_merge: {:#?}", conflict);
        // println!("local: {:#?}", local);
        // println!("remote: {:#?}", remote);

        if conflict.identity {
            let hard_conflict = self
                .auto_merge_identity(options, &mut force_merge_outcome)
                .await?;
            has_hard_conflict = has_hard_conflict || hard_conflict;
        }

        if conflict.account {
            let hard_conflict = self
                .auto_merge_account(options, &mut force_merge_outcome)
                .await?;
            has_hard_conflict = has_hard_conflict || hard_conflict;
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
            let hard_conflict = self
                .auto_merge_folder(
                    options,
                    &local,
                    folder_id,
                    &mut force_merge_outcome,
                )
                .await?;
            has_hard_conflict = has_hard_conflict || hard_conflict;
        }

        if has_hard_conflict {
            tracing::debug!(
                outcome = ?force_merge_outcome,
                "auto_merge::hard_conflict");
            let mut account = self.account.lock().await;
            account.sign_out().await?;
        }

        Ok(())
    }

    async fn auto_merge_identity(
        &self,
        options: &SyncOptions,
        outcome: &mut MergeOutcome,
    ) -> Result<bool> {
        tracing::debug!("auto_merge::identity");

        let req = CommitScanRequest {
            log_type: EventLogType::Identity,
            offset: None,
            limit: PROOF_SCAN_LIMIT,
            ascending: false,
        };
        match self.scan_proofs(req).await {
            Ok(Some((ancestor_commit, proof))) => {
                self.try_merge_from_ancestor::<WriteEvent>(
                    EventLogType::Identity,
                    ancestor_commit,
                    proof,
                )
                .await?;
                Ok(false)
            }
            Err(e) => match e {
                Error::HardConflict => {
                    self.identity_hard_conflict(options, outcome).await?;
                    Ok(true)
                }
                _ => Err(e),
            },
            _ => Err(Error::HardConflict),
        }
    }

    async fn identity_hard_conflict(
        &self,
        options: &SyncOptions,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        match &options.hard_conflict_resolver {
            HardConflictResolver::AutomaticFetch => {
                let request = CommitDiffRequest {
                    log_type: EventLogType::Identity,
                    from_hash: None,
                };
                let response = self.client.diff(&request).await?;
                let patch = Patch::<WriteEvent>::new(response.patch);
                let diff = FolderDiff {
                    patch,
                    before: response.checkpoint,
                    last_commit: None,
                    after: None,
                };
                let mut account = self.account.lock().await;
                Ok(account.force_merge_identity(diff, outcome).await?)
            }
        }
    }

    async fn auto_merge_account(
        &self,
        options: &SyncOptions,
        outcome: &mut MergeOutcome,
    ) -> Result<bool> {
        tracing::debug!("auto_merge::account");

        let req = CommitScanRequest {
            log_type: EventLogType::Account,
            offset: None,
            limit: PROOF_SCAN_LIMIT,
            ascending: false,
        };

        match self.scan_proofs(req).await {
            Ok(Some((ancestor_commit, proof))) => {
                self.try_merge_from_ancestor::<WriteEvent>(
                    EventLogType::Account,
                    ancestor_commit,
                    proof,
                )
                .await?;
                Ok(false)
            }
            Err(e) => match e {
                Error::HardConflict => {
                    self.account_hard_conflict(options, outcome).await?;
                    Ok(true)
                }
                _ => Err(e),
            },
            _ => Err(Error::HardConflict),
        }
    }

    async fn account_hard_conflict(
        &self,
        options: &SyncOptions,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        match &options.hard_conflict_resolver {
            HardConflictResolver::AutomaticFetch => {
                let request = CommitDiffRequest {
                    log_type: EventLogType::Account,
                    from_hash: None,
                };
                let response = self.client.diff(&request).await?;
                let patch = Patch::<AccountEvent>::new(response.patch);
                let diff = AccountDiff {
                    patch,
                    before: response.checkpoint,
                    last_commit: None,
                    after: None,
                };
                let mut account = self.account.lock().await;
                Ok(account.force_merge_account(diff, outcome).await?)
            }
        }
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
        options: &SyncOptions,
        _local_status: &SyncStatus,
        folder_id: &VaultId,
        outcome: &mut MergeOutcome,
    ) -> Result<bool> {
        tracing::debug!(folder_id = %folder_id, "auto_merge::folder");

        let req = CommitScanRequest {
            log_type: EventLogType::Folder(*folder_id),
            offset: None,
            limit: PROOF_SCAN_LIMIT,
            ascending: false,
        };
        match self.scan_proofs(req).await {
            Ok(Some((ancestor_commit, proof))) => {
                self.try_merge_from_ancestor::<WriteEvent>(
                    EventLogType::Folder(*folder_id),
                    ancestor_commit,
                    proof,
                )
                .await?;
                Ok(false)
            }
            Err(e) => match e {
                Error::HardConflict => {
                    self.folder_hard_conflict(folder_id, options, outcome)
                        .await?;
                    Ok(true)
                }
                _ => Err(e),
            },
            _ => Err(Error::HardConflict),
        }
    }

    async fn folder_hard_conflict(
        &self,
        folder_id: &VaultId,
        options: &SyncOptions,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        match &options.hard_conflict_resolver {
            HardConflictResolver::AutomaticFetch => {
                let request = CommitDiffRequest {
                    log_type: EventLogType::Folder(*folder_id),
                    from_hash: None,
                };
                let response = self.client.diff(&request).await?;
                let patch = Patch::<WriteEvent>::new(response.patch);
                let diff = FolderDiff {
                    patch,
                    before: response.checkpoint,
                    last_commit: None,
                    after: None,
                };
                let mut account = self.account.lock().await;
                Ok(account
                    .force_merge_folder(folder_id, diff, outcome)
                    .await?)
            }
        }
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
            from_hash: Some(commit),
        };
        let remote_patch = self.client.diff(&request).await?.patch;

        let result = self.merge_patches(local_patch, remote_patch).await?;

        match result {
            AutoMerge::RewindLocal(events) => {
                let local_patch = self
                    .rewind_local(&log_type, commit, proof, events)
                    .await?;

                let success =
                    matches!(local_patch, CheckedPatch::Success(_, _));

                if success {
                    tracing::info!("auto_merge::rewind_local::success");
                }
            }
            AutoMerge::PushRemote(events) => {
                let (remote_patch, local_patch) = self
                    .push_remote::<T>(&log_type, commit, proof, events)
                    .await?;

                let success =
                    matches!(remote_patch, CheckedPatch::Success(_, _))
                        && matches!(
                            local_patch,
                            Some(CheckedPatch::Success(_, _))
                        );

                if success {
                    tracing::info!("auto_merge::push_remote::success");
                }
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
    ) -> Result<CheckedPatch> {
        tracing::debug!(
          log_type = ?log_type,
          commit = %commit,
          length = %events.len(),
          "auto_merge::rewind_local",
        );

        // Rewind the event log to the target commit
        let records = self.rewind_event_log(log_type, &commit).await?;

        let mut outcome = MergeOutcome::default();

        // Merge the events after rewinding
        let checked_patch = {
            let mut account = self.account.lock().await;
            match &log_type {
                EventLogType::Identity => {
                    let patch = Patch::<WriteEvent>::new(events);
                    let diff = FolderDiff {
                        last_commit: Some(commit),
                        before: proof,
                        patch,
                        after: None,
                    };
                    account.merge_identity(diff, &mut outcome).await?
                }
                EventLogType::Account => {
                    let patch = Patch::<AccountEvent>::new(events);
                    let diff = AccountDiff {
                        last_commit: Some(commit),
                        before: proof,
                        patch,
                        after: None,
                    };
                    account.merge_account(diff, &mut outcome).await?
                }
                #[cfg(feature = "device")]
                EventLogType::Device => {
                    let patch = Patch::<DeviceEvent>::new(events);
                    let diff = DeviceDiff {
                        last_commit: Some(commit),
                        before: proof,
                        patch,
                        after: None,
                    };
                    account.merge_device(diff, &mut outcome).await?
                }
                #[cfg(feature = "files")]
                EventLogType::Files => {
                    let patch = Patch::<FileEvent>::new(events);
                    let diff = FileDiff {
                        last_commit: Some(commit),
                        before: proof,
                        patch,
                        after: None,
                    };
                    account.merge_files(diff, &mut outcome).await?
                }
                EventLogType::Folder(id) => {
                    let patch = Patch::<WriteEvent>::new(events);
                    let diff = FolderDiff {
                        last_commit: Some(commit),
                        before: proof,
                        patch,
                        after: None,
                    };
                    account.merge_folder(id, diff, &mut outcome).await?
                }
                EventLogType::Noop => unreachable!(),
            }
        };

        if let CheckedPatch::Conflict { head, .. } = &checked_patch {
            tracing::warn!(
                head = ?head,
                num_records = ?records.len(),
                "auto_merge::rollback_rewind");

            self.rollback_rewind(log_type, records).await?;
        }

        Ok(checked_patch)
    }

    async fn rollback_rewind(
        &self,
        log_type: &EventLogType,
        records: Vec<EventRecord>,
    ) -> Result<()> {
        let account = self.account.lock().await;
        match log_type {
            EventLogType::Identity => {
                let log = account.identity_log().await?;
                let mut event_log = log.write().await;
                event_log.apply_records(records).await?;
            }
            EventLogType::Account => {
                let log = account.account_log().await?;
                let mut event_log = log.write().await;
                event_log.apply_records(records).await?;
            }
            #[cfg(feature = "device")]
            EventLogType::Device => {
                let log = account.device_log().await?;
                let mut event_log = log.write().await;
                event_log.apply_records(records).await?;
            }
            #[cfg(feature = "files")]
            EventLogType::Files => {
                let log = account.file_log().await?;
                let mut event_log = log.write().await;
                event_log.apply_records(records).await?;
            }
            EventLogType::Folder(id) => {
                let log = account.folder_log(id).await?;
                let mut event_log = log.write().await;
                event_log.apply_records(records).await?;
            }
            EventLogType::Noop => unreachable!(),
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
    ) -> Result<(CheckedPatch, Option<CheckedPatch>)>
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
            proof: proof.clone(),
            patch: events.clone(),
        };

        let remote_patch = self.client.patch(&req).await?;
        let local_patch = match &remote_patch {
            CheckedPatch::Noop => unreachable!(),
            CheckedPatch::Success(_, _) => {
                let local_patch = self
                    .rewind_local(log_type, commit, proof, events)
                    .await?;
                Some(local_patch)
            }
            CheckedPatch::Conflict { head, contains } => {
                tracing::error!(
                  head = ?head,
                  contains = ?contains,
                  "auto_merge::patch::conflict",
                );
                None
            }
        };

        Ok((remote_patch, local_patch))
    }

    /// Rewind an event log to a specific commit.
    async fn rewind_event_log(
        &self,
        log_type: &EventLogType,
        commit: &CommitHash,
    ) -> Result<Vec<EventRecord>> {
        tracing::debug!(
          log_type = ?log_type,
          commit = %commit,
          "automerge::rewind_event_log",
        );
        // Rewind the event log
        let account = self.account.lock().await;
        Ok(match &log_type {
            EventLogType::Identity => {
                let log = account.identity_log().await?;
                let mut event_log = log.write().await;
                event_log.rewind(commit).await?
            }
            EventLogType::Account => {
                let log = account.account_log().await?;
                let mut event_log = log.write().await;
                event_log.rewind(commit).await?
            }
            #[cfg(feature = "device")]
            EventLogType::Device => {
                let log = account.device_log().await?;
                let mut event_log = log.write().await;
                event_log.rewind(commit).await?
            }
            #[cfg(feature = "files")]
            EventLogType::Files => {
                let log = account.file_log().await?;
                let mut event_log = log.write().await;
                event_log.rewind(commit).await?
            }
            EventLogType::Folder(id) => {
                let log = account.folder_log(id).await?;
                let mut event_log = log.write().await;
                event_log.rewind(commit).await?
            }
            EventLogType::Noop => unreachable!(),
        })
    }

    /// Scan the remote for proofs that match this client.
    async fn scan_proofs(
        &self,
        request: CommitScanRequest,
    ) -> Result<Option<(CommitHash, CommitProof)>> {
        tracing::debug!(request = ?request, "auto_merge::scan_proofs");

        let leaves = {
            let account = self.account.lock().await;
            match &request.log_type {
                EventLogType::Identity => {
                    let log = account.identity_log().await?;
                    let event_log = log.read().await;
                    event_log.tree().leaves().unwrap_or_default()
                }
                EventLogType::Account => {
                    let log = account.account_log().await?;
                    let event_log = log.read().await;
                    event_log.tree().leaves().unwrap_or_default()
                }
                #[cfg(feature = "device")]
                EventLogType::Device => {
                    let log = account.device_log().await?;
                    let event_log = log.read().await;
                    event_log.tree().leaves().unwrap_or_default()
                }
                #[cfg(feature = "files")]
                EventLogType::Files => {
                    let log = account.file_log().await?;
                    let event_log = log.read().await;
                    event_log.tree().leaves().unwrap_or_default()
                }
                EventLogType::Folder(id) => {
                    let log = account.folder_log(id).await?;
                    let event_log = log.read().await;
                    event_log.tree().leaves().unwrap_or_default()
                }
                EventLogType::Noop => unreachable!(),
            }
        };

        self.iterate_scan_proofs(request, &leaves).await
    }

    /// Scan the remote for proofs that match this client.
    #[async_recursion]
    async fn iterate_scan_proofs(
        &self,
        request: CommitScanRequest,
        leaves: &[[u8; 32]],
    ) -> Result<Option<(CommitHash, CommitProof)>> {
        tracing::debug!(request = ?request, "auto_merge::iterate_scan_proofs");

        let response = self.client.scan(&request).await?;

        // If the server gave us a first proof and we don't
        // have it in our event log then there is no point scanning
        // as we know the trees have diverged
        if let Some(first_proof) = &response.first_proof {
            let (verified, _) = first_proof.verify_leaves(leaves);
            if !verified {
                return Err(Error::HardConflict);
            }
        }

        if !response.proofs.is_empty() {
            // Proofs are returned in the event log order
            // but we always want to scan from the end of
            // the event log so reverse the iteration
            for proof in response.proofs.iter().rev() {
                // Find the last matching commit from the indices
                // to prove
                if let Some(commit_hash) = self.compare_proof(proof, leaves) {
                    // Compute the root hash and proof for the
                    // matched index
                    let index = proof.indices.last().copied().unwrap();
                    let new_leaves = &leaves[0..=index];
                    let mut new_leaves = new_leaves.to_vec();
                    let mut new_tree = CommitTree::new();
                    new_tree.append(&mut new_leaves);
                    new_tree.commit();

                    let checkpoint_proof = new_tree.head()?;
                    return Ok(Some((commit_hash, checkpoint_proof)));
                }
            }

            // Try to scan more proofs
            let mut req = request.clone();
            req.offset = Some(response.offset);
            self.iterate_scan_proofs(req, leaves).await
        } else {
            Err(Error::HardConflict)
        }
    }

    /// Determine if a local event log contains a proof
    /// received from the server.
    fn compare_proof(
        &self,
        proof: &CommitProof,
        leaves: &[[u8; 32]],
    ) -> Option<CommitHash> {
        let (verified, leaves) = proof.verify_leaves(leaves);

        tracing::trace!(
            proof = ?proof,
            verified = ?verified,
            "auto_merge::compare_proof",
        );

        if verified {
            leaves.last().copied().map(CommitHash)
        } else {
            None
        }
    }
}
