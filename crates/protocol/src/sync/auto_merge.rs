//! Implements auto merge logic for a remote.
use crate::{
    AsConflict, ConflictError, DiffRequest, PatchRequest, ScanRequest,
    SyncClient,
};
use async_trait::async_trait;
use sos_sdk::{
    account::Account,
    commit::{CommitHash, CommitProof, CommitTree},
    events::{
        AccountDiff, AccountEvent, CheckedPatch, Diff, EventLogExt,
        EventRecord, FolderDiff, Patch, WriteEvent,
    },
    storage::StorageEventLogs,
    vault::VaultId,
};

use crate::{
    EventLogType, ForceMerge, HardConflictResolver, MaybeConflict, Merge,
    MergeOutcome, SyncOptions, SyncStatus,
};
use std::collections::HashSet;
use tracing::instrument;

const PROOF_SCAN_LIMIT: u16 = 32;

use sos_sdk::events::{DeviceDiff, DeviceEvent};

#[cfg(feature = "files")]
use sos_sdk::events::{FileDiff, FileEvent};

use super::RemoteSyncHandler;

/// State used while scanning commit proofs on a remote data source.
#[doc(hidden)]
pub enum ScanState {
    Result((CommitHash, CommitProof)),
    Continue(ScanRequest),
    Exhausted,
}

/// Whether to apply an auto merge to local or remote.
#[doc(hidden)]
pub enum AutoMergeStatus {
    /// Apply the events to the local event log.
    RewindLocal(Vec<EventRecord>),
    /// Push events to the remote.
    PushRemote(Vec<EventRecord>),
}

/// Support for auto merge on sync.
#[async_trait]
pub trait AutoMerge: RemoteSyncHandler {
    /// Execute the sync operation.
    ///
    /// If the account does not exist it is created
    /// on the remote, otherwise the account is synced.
    #[doc(hidden)]
    async fn execute_sync(
        &self,
        options: &SyncOptions,
    ) -> Result<Option<MergeOutcome>, Self::Error> {
        let exists = self.client().account_exists(self.address()).await?;
        if exists {
            let sync_status =
                self.client().sync_status(self.address()).await?;
            match self.sync_account(sync_status).await {
                Ok(outcome) => Ok(Some(outcome)),
                Err(e) => {
                    if e.is_conflict() {
                        let conflict = e.take_conflict().unwrap();
                        match conflict {
                            ConflictError::Soft {
                                conflict,
                                local,
                                remote,
                            } => {
                                let outcome = self
                                    .auto_merge(
                                        options, conflict, local, remote,
                                    )
                                    .await?;
                                Ok(Some(outcome))
                            }
                            _ => Err(conflict.into()),
                        }
                    } else {
                        Err(e)
                    }
                }
            }
        } else {
            self.create_account().await?;
            Ok(None)
        }
    }

    #[doc(hidden)]
    async fn auto_merge_scan<T>(
        &self,
        log_id: &'static str,
        log_type: EventLogType,
    ) -> Result<bool, <Self as RemoteSyncHandler>::Error>
    where
        T: Default + Send + Sync,
    {
        tracing::debug!(log_id);

        let req = ScanRequest {
            log_type,
            offset: 0,
            limit: PROOF_SCAN_LIMIT,
        };
        match self.scan_proofs(req).await {
            Ok(Some((ancestor_commit, proof))) => {
                self.try_merge_from_ancestor::<T>(
                    EventLogType::Identity,
                    ancestor_commit,
                    proof,
                )
                .await?;
                Ok(false)
            }
            Err(e) => {
                if e.is_hard_conflict() {
                    Ok(true)
                } else {
                    Err(e)
                }
            }
            _ => Err(ConflictError::Hard.into()),
        }
    }

    /// Auto merge identity folders.
    async fn auto_merge_identity(
        &self,
        options: &SyncOptions,
        outcome: &mut MergeOutcome,
    ) -> Result<bool, <Self as RemoteSyncHandler>::Error> {
        let handle_conflict = self
            .auto_merge_scan::<WriteEvent>(
                "auto_merge::identity",
                EventLogType::Identity,
            )
            .await?;
        if handle_conflict {
            self.identity_hard_conflict(options, outcome).await?;
        }
        Ok(handle_conflict)
    }

    /// Auto merge account events.
    async fn auto_merge_account(
        &self,
        options: &SyncOptions,
        outcome: &mut MergeOutcome,
    ) -> Result<bool, <Self as RemoteSyncHandler>::Error> {
        let handle_conflict = self
            .auto_merge_scan::<AccountEvent>(
                "auto_merge::account",
                EventLogType::Account,
            )
            .await?;
        if handle_conflict {
            self.account_hard_conflict(options, outcome).await?;
        }
        Ok(handle_conflict)
    }

    /// Auto merge device events.
    async fn auto_merge_device(
        &self,
        options: &SyncOptions,
        outcome: &mut MergeOutcome,
    ) -> Result<bool, <Self as RemoteSyncHandler>::Error> {
        let handle_conflict = self
            .auto_merge_scan::<DeviceEvent>(
                "auto_merge::device",
                EventLogType::Device,
            )
            .await?;
        if handle_conflict {
            self.device_hard_conflict(options, outcome).await?;
        }
        Ok(handle_conflict)
    }

    /// Auto merge file events.
    #[cfg(feature = "files")]
    async fn auto_merge_files(
        &self,
        options: &SyncOptions,
        outcome: &mut MergeOutcome,
    ) -> Result<bool, <Self as RemoteSyncHandler>::Error> {
        let handle_conflict = self
            .auto_merge_scan::<FileEvent>(
                "auto_merge::files",
                EventLogType::Files,
            )
            .await?;
        if handle_conflict {
            self.files_hard_conflict(options, outcome).await?;
        }
        Ok(handle_conflict)
    }

    #[doc(hidden)]
    async fn hard_conflict_diff<EventType>(
        &self,
        log_id: &'static str,
        log_type: EventLogType,
        options: &SyncOptions,
    ) -> Result<Diff<EventType>, <Self as RemoteSyncHandler>::Error> {
        match &options.hard_conflict_resolver {
            HardConflictResolver::AutomaticFetch => {
                tracing::debug!(log_id);

                let request = DiffRequest {
                    log_type,
                    from_hash: None,
                };
                let response =
                    self.client().diff(self.address(), request).await?;
                let patch = Patch::<EventType>::new(response.patch);
                let diff =
                    Diff::<EventType>::new(patch, response.checkpoint, None);
                Ok(diff)
            }
        }
    }

    #[doc(hidden)]
    async fn identity_hard_conflict(
        &self,
        options: &SyncOptions,
        outcome: &mut MergeOutcome,
    ) -> Result<(), <Self as RemoteSyncHandler>::Error> {
        let diff = self
            .hard_conflict_diff::<WriteEvent>(
                "hard_conflict::force_merge::identity",
                EventLogType::Identity,
                options,
            )
            .await?;

        let account = self.account();
        let mut account = account.lock().await;
        Ok(account.force_merge_identity(diff, outcome).await?)
    }

    #[doc(hidden)]
    async fn account_hard_conflict(
        &self,
        options: &SyncOptions,
        outcome: &mut MergeOutcome,
    ) -> Result<(), <Self as RemoteSyncHandler>::Error> {
        let diff = self
            .hard_conflict_diff::<AccountEvent>(
                "hard_conflict::force_merge::account",
                EventLogType::Account,
                options,
            )
            .await?;

        let account = self.account();
        let mut account = account.lock().await;
        Ok(account.force_merge_account(diff, outcome).await?)
    }

    #[doc(hidden)]
    async fn device_hard_conflict(
        &self,
        options: &SyncOptions,
        outcome: &mut MergeOutcome,
    ) -> Result<(), <Self as RemoteSyncHandler>::Error> {
        let diff = self
            .hard_conflict_diff::<DeviceEvent>(
                "hard_conflict::force_merge::device",
                EventLogType::Device,
                options,
            )
            .await?;

        let account = self.account();
        let mut account = account.lock().await;
        Ok(account.force_merge_device(diff, outcome).await?)
    }

    #[doc(hidden)]
    #[cfg(feature = "files")]
    async fn files_hard_conflict(
        &self,
        options: &SyncOptions,
        outcome: &mut MergeOutcome,
    ) -> Result<(), <Self as RemoteSyncHandler>::Error> {
        let diff = self
            .hard_conflict_diff::<FileEvent>(
                "hard_conflict::force_merge::files",
                EventLogType::Files,
                options,
            )
            .await?;

        let account = self.account();
        let mut account = account.lock().await;
        Ok(account.force_merge_files(diff, outcome).await?)
    }

    /// Try to auto merge on conflict.
    ///
    /// Searches the remote event log for a common ancestor and
    /// attempts to merge commits from the common ancestor with the
    /// diff that would have been applied.
    ///
    /// Once the changes have been merged a force update of the
    /// server is necessary.
    #[instrument(skip_all)]
    async fn auto_merge(
        &self,
        options: &SyncOptions,
        conflict: MaybeConflict,
        local: SyncStatus,
        _remote: SyncStatus,
    ) -> Result<MergeOutcome, <Self as RemoteSyncHandler>::Error> {
        let mut force_merge_outcome = MergeOutcome::default();
        let mut has_hard_conflict = false;

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

        if conflict.device {
            let hard_conflict = self
                .auto_merge_device(options, &mut force_merge_outcome)
                .await?;
            has_hard_conflict = has_hard_conflict || hard_conflict;
        }

        #[cfg(feature = "files")]
        if conflict.files {
            let hard_conflict = self
                .auto_merge_files(options, &mut force_merge_outcome)
                .await?;
            has_hard_conflict = has_hard_conflict || hard_conflict;
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
                "hard_conflict::sign_out");
            let account = self.account();
            let mut account = account.lock().await;
            account.sign_out().await?;
        }

        Ok(force_merge_outcome)
    }

    /// Auto merge a folder.
    async fn auto_merge_folder(
        &self,
        options: &SyncOptions,
        _local_status: &SyncStatus,
        folder_id: &VaultId,
        outcome: &mut MergeOutcome,
    ) -> Result<bool, <Self as RemoteSyncHandler>::Error> {
        tracing::debug!(folder_id = %folder_id, "auto_merge::folder");

        let req = ScanRequest {
            log_type: EventLogType::Folder(*folder_id),
            offset: 0,
            limit: PROOF_SCAN_LIMIT,
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
            Err(e) => {
                if e.is_hard_conflict() {
                    self.folder_hard_conflict(folder_id, options, outcome)
                        .await?;
                    Ok(true)
                } else {
                    Err(e)
                }
            }
            _ => Err(ConflictError::Hard.into()),
        }
    }

    #[doc(hidden)]
    async fn folder_hard_conflict(
        &self,
        folder_id: &VaultId,
        options: &SyncOptions,
        outcome: &mut MergeOutcome,
    ) -> Result<(), <Self as RemoteSyncHandler>::Error> {
        match &options.hard_conflict_resolver {
            HardConflictResolver::AutomaticFetch => {
                let request = DiffRequest {
                    log_type: EventLogType::Folder(*folder_id),
                    from_hash: None,
                };
                let response =
                    self.client().diff(self.address(), request).await?;
                let patch = Patch::<WriteEvent>::new(response.patch);
                let diff = FolderDiff {
                    patch,
                    checkpoint: response.checkpoint,
                    last_commit: None,
                };
                let account = self.account();
                let mut account = account.lock().await;
                Ok(account
                    .force_merge_folder(folder_id, diff, outcome)
                    .await?)
            }
        }
    }

    /// Try to merge from a shared ancestor commit.
    #[doc(hidden)]
    async fn try_merge_from_ancestor<T>(
        &self,
        log_type: EventLogType,
        commit: CommitHash,
        proof: CommitProof,
    ) -> Result<(), <Self as RemoteSyncHandler>::Error>
    where
        T: Default + Send + Sync,
    {
        tracing::debug!(commit = %commit, "auto_merge::try_merge_from_ancestor");

        // Get the patch from local
        let local_patch = {
            let account = self.account();
            let account = account.lock().await;
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
            }
        };

        // Fetch the patch of remote events
        let request = DiffRequest {
            log_type,
            from_hash: Some(commit),
        };
        let remote_patch =
            self.client().diff(self.address(), request).await?.patch;

        let result = self.merge_patches(local_patch, remote_patch).await?;

        match result {
            AutoMergeStatus::RewindLocal(events) => {
                let local_patch = self
                    .rewind_local(&log_type, commit, proof, events)
                    .await?;

                let success = matches!(local_patch, CheckedPatch::Success(_));

                if success {
                    tracing::info!("auto_merge::rewind_local::success");
                }
            }
            AutoMergeStatus::PushRemote(events) => {
                let (remote_patch, local_patch) = self
                    .push_remote::<T>(&log_type, commit, proof, events)
                    .await?;

                let success =
                    matches!(remote_patch, CheckedPatch::Success(_))
                        && matches!(
                            local_patch,
                            Some(CheckedPatch::Success(_))
                        );

                if success {
                    tracing::info!("auto_merge::push_remote::success");
                }
            }
        }

        Ok(())
    }

    #[doc(hidden)]
    async fn merge_patches(
        &self,
        mut local: Vec<EventRecord>,
        remote: Vec<EventRecord>,
    ) -> Result<AutoMergeStatus, <Self as RemoteSyncHandler>::Error> {
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
            return Ok(AutoMergeStatus::RewindLocal(remote));
        }

        // Combine the event records
        local.extend(remote.into_iter());

        // Sort by time so the more recent changes will win (LWW)
        local.sort_by(|a, b| a.time().cmp(b.time()));

        Ok(AutoMergeStatus::PushRemote(local))
    }

    /// Rewind a local event log and apply the events.
    #[doc(hidden)]
    async fn rewind_local(
        &self,
        log_type: &EventLogType,
        commit: CommitHash,
        proof: CommitProof,
        events: Vec<EventRecord>,
    ) -> Result<CheckedPatch, <Self as RemoteSyncHandler>::Error> {
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
            let account = self.account();
            let mut account = account.lock().await;
            match &log_type {
                EventLogType::Identity => {
                    let patch = Patch::<WriteEvent>::new(events);
                    let diff = FolderDiff {
                        last_commit: Some(commit),
                        checkpoint: proof,
                        patch,
                    };
                    account.merge_identity(diff, &mut outcome).await?
                }
                EventLogType::Account => {
                    let patch = Patch::<AccountEvent>::new(events);
                    let diff = AccountDiff {
                        last_commit: Some(commit),
                        checkpoint: proof,
                        patch,
                    };
                    account.merge_account(diff, &mut outcome).await?.0
                }
                EventLogType::Device => {
                    let patch = Patch::<DeviceEvent>::new(events);
                    let diff = DeviceDiff {
                        last_commit: Some(commit),
                        checkpoint: proof,
                        patch,
                    };
                    account.merge_device(diff, &mut outcome).await?
                }
                #[cfg(feature = "files")]
                EventLogType::Files => {
                    let patch = Patch::<FileEvent>::new(events);
                    let diff = FileDiff {
                        last_commit: Some(commit),
                        checkpoint: proof,
                        patch,
                    };
                    account.merge_files(diff, &mut outcome).await?
                }
                EventLogType::Folder(id) => {
                    let patch = Patch::<WriteEvent>::new(events);
                    let diff = FolderDiff {
                        last_commit: Some(commit),
                        checkpoint: proof,
                        patch,
                    };
                    account.merge_folder(id, diff, &mut outcome).await?.0
                }
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

    #[doc(hidden)]
    async fn rollback_rewind(
        &self,
        log_type: &EventLogType,
        records: Vec<EventRecord>,
    ) -> Result<(), <Self as RemoteSyncHandler>::Error> {
        let account = self.account();
        let account = account.lock().await;
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
        }

        Ok(())
    }

    /// Push the events to a remote and rewind local.
    #[doc(hidden)]
    async fn push_remote<T>(
        &self,
        log_type: &EventLogType,
        commit: CommitHash,
        proof: CommitProof,
        events: Vec<EventRecord>,
    ) -> Result<
        (CheckedPatch, Option<CheckedPatch>),
        <Self as RemoteSyncHandler>::Error,
    >
    where
        T: Default + Send + Sync,
    {
        tracing::debug!(
          log_type = ?log_type,
          commit = %commit,
          length = %events.len(),
          "auto_merge::push_remote",
        );

        let req = PatchRequest {
            log_type: *log_type,
            commit: Some(commit),
            proof: proof.clone(),
            patch: events.clone(),
        };

        let remote_patch = self
            .client()
            .patch(self.address(), req)
            .await?
            .checked_patch;
        let local_patch = match &remote_patch {
            CheckedPatch::Success(_) => {
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
    #[doc(hidden)]
    async fn rewind_event_log(
        &self,
        log_type: &EventLogType,
        commit: &CommitHash,
    ) -> Result<Vec<EventRecord>, <Self as RemoteSyncHandler>::Error> {
        tracing::debug!(
          log_type = ?log_type,
          commit = %commit,
          "automerge::rewind_event_log",
        );
        // Rewind the event log
        let account = self.account();
        let account = account.lock().await;
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
        })
    }

    /// Scan the remote for proofs that match this client.
    #[doc(hidden)]
    async fn scan_proofs(
        &self,
        request: ScanRequest,
    ) -> Result<
        Option<(CommitHash, CommitProof)>,
        <Self as RemoteSyncHandler>::Error,
    > {
        tracing::debug!(request = ?request, "auto_merge::scan_proofs");

        let leaves = {
            let account = self.account();
            let account = account.lock().await;
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
            }
        };

        let mut req = request.clone();
        loop {
            match self.iterate_scan_proofs(req.clone(), &leaves).await? {
                ScanState::Result(value) => return Ok(Some(value)),
                ScanState::Continue(scan) => req = scan,
                ScanState::Exhausted => return Ok(None),
            }
        }
    }

    /// Scan the remote for proofs that match this client.
    #[doc(hidden)]
    async fn iterate_scan_proofs(
        &self,
        request: ScanRequest,
        leaves: &[[u8; 32]],
    ) -> Result<ScanState, <Self as RemoteSyncHandler>::Error> {
        tracing::debug!(
          request = ?request,
          "auto_merge::iterate_scan_proofs");

        let response =
            self.client().scan(self.address(), request.clone()).await?;

        // If the server gave us a first proof and we don't
        // have it in our event log then there is no point scanning
        // as we know the trees have diverged
        if let Some(first_proof) = &response.first_proof {
            let (verified, _) = first_proof.verify_leaves(leaves);
            if !verified {
                return Err(ConflictError::Hard.into());
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
                    return Ok(ScanState::Result((
                        commit_hash,
                        checkpoint_proof,
                    )));
                }
            }

            // Try to scan more proofs
            let mut req = request;
            req.offset = response.offset;

            Ok(ScanState::Continue(req))
        } else {
            Ok(ScanState::Exhausted)
        }
    }

    /// Determine if a local event log contains a proof
    /// received from the server.
    #[doc(hidden)]
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
