//! Implements auto merge logic for a remote.
use crate::{
    client::{Error, RemoteBridge, Result, SyncClient},
    protocol::{DiffRequest, PatchRequest, ScanRequest},
};
use crate::{
    protocol::sync::{
        EventLogType, ForceMerge, HardConflictResolver, MaybeConflict, Merge,
        MergeOutcome, SyncOptions, SyncStatus,
    },
    sdk::{
        account::Account,
        commit::{CommitHash, CommitProof, CommitTree},
        events::{
            AccountDiff, AccountEvent, CheckedPatch, EventLogExt,
            EventRecord, FolderDiff, Patch, WriteEvent,
        },
        storage::StorageEventLogs,
        vault::VaultId,
    },
};
use async_recursion::async_recursion;
use std::collections::HashSet;
use tracing::instrument;

const PROOF_SCAN_LIMIT: u16 = 32;

#[cfg(feature = "device")]
use sos_sdk::events::{DeviceDiff, DeviceEvent};

#[cfg(feature = "files")]
use sos_sdk::events::{FileDiff, FileEvent};

/// Implements the auto merge logic for an event log type.
macro_rules! auto_merge_impl {
    ($log_id:expr, $fn_name:ident, $log_type:expr, $event_type:ident, $conflict_fn:ident) => {
        async fn $fn_name(
            &self,
            options: &SyncOptions,
            outcome: &mut MergeOutcome,
        ) -> Result<bool> {
            tracing::debug!($log_id);

            let req = ScanRequest {
                log_type: $log_type,
                offset: 0,
                limit: PROOF_SCAN_LIMIT,
            };
            match self.scan_proofs(req).await {
                Ok(Some((ancestor_commit, proof))) => {
                    self.try_merge_from_ancestor::<$event_type>(
                        EventLogType::Identity,
                        ancestor_commit,
                        proof,
                    )
                    .await?;
                    Ok(false)
                }
                Err(e) => match e {
                    Error::HardConflict => {
                        self.$conflict_fn(options, outcome).await?;
                        Ok(true)
                    }
                    _ => Err(e),
                },
                _ => Err(Error::HardConflict),
            }
        }
    };
}

/// Implements the hard conflict resolution logic for an event log type.
macro_rules! auto_merge_conflict_impl {
    ($log_id:expr, $fn_name:ident, $log_type:expr, $event_type:ident, $diff_type:ident, $merge_fn:ident) => {
        async fn $fn_name(
            &self,
            options: &SyncOptions,
            outcome: &mut MergeOutcome,
        ) -> Result<()> {
            match &options.hard_conflict_resolver {
                HardConflictResolver::AutomaticFetch => {
                    tracing::debug!($log_id);

                    let request = DiffRequest {
                        log_type: $log_type,
                        from_hash: None,
                    };
                    let response = self.client.diff(request).await?;
                    let patch = Patch::<$event_type>::new(response.patch);
                    let diff = $diff_type {
                        patch,
                        checkpoint: response.checkpoint,
                        last_commit: None,
                    };
                    let mut account = self.account.lock().await;
                    Ok(account.$merge_fn(diff, outcome).await?)
                }
            }
        }
    };
}

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
            let mut account = self.account.lock().await;
            account.sign_out().await?;
        }

        Ok(())
    }

    auto_merge_impl!(
        "auto_merge::identity",
        auto_merge_identity,
        EventLogType::Identity,
        WriteEvent,
        identity_hard_conflict
    );

    auto_merge_conflict_impl!(
        "hard_conflict::force_merge::identity",
        identity_hard_conflict,
        EventLogType::Identity,
        WriteEvent,
        FolderDiff,
        force_merge_identity
    );

    auto_merge_impl!(
        "auto_merge::account",
        auto_merge_account,
        EventLogType::Account,
        AccountEvent,
        account_hard_conflict
    );

    auto_merge_conflict_impl!(
        "hard_conflict::force_merge::account",
        account_hard_conflict,
        EventLogType::Account,
        AccountEvent,
        AccountDiff,
        force_merge_account
    );

    #[cfg(feature = "device")]
    auto_merge_impl!(
        "auto_merge::device",
        auto_merge_device,
        EventLogType::Device,
        DeviceEvent,
        device_hard_conflict
    );

    #[cfg(feature = "device")]
    auto_merge_conflict_impl!(
        "hard_conflict::force_merge::device",
        device_hard_conflict,
        EventLogType::Device,
        DeviceEvent,
        DeviceDiff,
        force_merge_device
    );

    #[cfg(feature = "files")]
    auto_merge_impl!(
        "auto_merge::files",
        auto_merge_files,
        EventLogType::Files,
        FileEvent,
        files_hard_conflict
    );

    #[cfg(feature = "files")]
    auto_merge_conflict_impl!(
        "hard_conflict::force_merge::files",
        files_hard_conflict,
        EventLogType::Files,
        FileEvent,
        FileDiff,
        force_merge_files
    );

    async fn auto_merge_folder(
        &self,
        options: &SyncOptions,
        _local_status: &SyncStatus,
        folder_id: &VaultId,
        outcome: &mut MergeOutcome,
    ) -> Result<bool> {
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
                let request = DiffRequest {
                    log_type: EventLogType::Folder(*folder_id),
                    from_hash: None,
                };
                let response = self.client.diff(request).await?;
                let patch = Patch::<WriteEvent>::new(response.patch);
                let diff = FolderDiff {
                    patch,
                    checkpoint: response.checkpoint,
                    last_commit: None,
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
        T: Default + Send + Sync,
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
            }
        };

        // Fetch the patch of remote events
        let request = DiffRequest {
            log_type,
            from_hash: Some(commit),
        };
        let remote_patch = self.client.diff(request).await?.patch;

        let result = self.merge_patches(local_patch, remote_patch).await?;

        match result {
            AutoMerge::RewindLocal(events) => {
                let local_patch = self
                    .rewind_local(&log_type, commit, proof, events)
                    .await?;

                let success = matches!(local_patch, CheckedPatch::Success(_));

                if success {
                    tracing::info!("auto_merge::rewind_local::success");
                }
            }
            AutoMerge::PushRemote(events) => {
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
                    account.merge_account(diff, &mut outcome).await?
                }
                #[cfg(feature = "device")]
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
                    account.merge_folder(id, diff, &mut outcome).await?
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

        let remote_patch = self.client.patch(req).await?.checked_patch;
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
        })
    }

    /// Scan the remote for proofs that match this client.
    async fn scan_proofs(
        &self,
        request: ScanRequest,
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
            }
        };

        self.iterate_scan_proofs(request, &leaves).await
    }

    /// Scan the remote for proofs that match this client.
    #[async_recursion]
    async fn iterate_scan_proofs(
        &self,
        request: ScanRequest,
        leaves: &[[u8; 32]],
    ) -> Result<Option<(CommitHash, CommitProof)>> {
        tracing::debug!(request = ?request, "auto_merge::iterate_scan_proofs");

        let response = self.client.scan(request.clone()).await?;

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
            let mut req = request;
            req.offset = response.offset;
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
