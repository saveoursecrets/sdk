//! Core traits for storage that supports synchronization.
use crate::{
    CreateSet, DebugEventLogs, DebugEvents, DebugTree, MaybeDiff,
    MergeOutcome, SyncCompare, SyncDiff, SyncStatus, TrackedChanges,
    UpdateSet,
};
use async_trait::async_trait;
use indexmap::{IndexMap, IndexSet};
use sos_backend::{AccountEventLog, DeviceEventLog, FolderEventLog};
use sos_core::commit::CommitHash;
use sos_core::events::WriteEvent;
use sos_core::AccountId;
use sos_core::{
    commit::{CommitState, CommitTree, Comparison},
    events::{
        patch::{AccountDiff, CheckedPatch, DeviceDiff, FolderDiff},
        EventLog,
    },
    VaultId,
};
use sos_vault::Summary;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;

#[cfg(feature = "files")]
use {
    sos_backend::FileEventLog,
    sos_core::{events::patch::FileDiff, ExternalFile},
};

macro_rules! debug_tree_events {
    ($event_log:expr) => {{
        let root = $event_log.tree().root();
        let leaves: Vec<_> = $event_log
            .tree()
            .leaves()
            .unwrap_or_default()
            .into_iter()
            .map(CommitHash)
            .collect();
        DebugEvents {
            root,
            length: leaves.len(),
            leaves,
        }
    }};
}

/// References to the storage event logs.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait StorageEventLogs: Send + Sync + 'static {
    /// Error type for storage event logs.
    type Error: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<sos_backend::Error>
        + From<crate::Error>
        + Send
        + Sync
        + 'static;

    /// Clone of the identity log.
    async fn identity_log(
        &self,
    ) -> Result<Arc<RwLock<FolderEventLog>>, Self::Error>;

    /// Clone of the account log.
    async fn account_log(
        &self,
    ) -> Result<Arc<RwLock<AccountEventLog>>, Self::Error>;

    /// Clone of the device log.
    async fn device_log(
        &self,
    ) -> Result<Arc<RwLock<DeviceEventLog>>, Self::Error>;

    /// Clone of the file log.
    #[cfg(feature = "files")]
    async fn file_log(
        &self,
    ) -> Result<Arc<RwLock<FileEventLog>>, Self::Error>;

    /// Canonical collection of files reduced from the file event log.
    #[cfg(feature = "files")]
    async fn canonical_files(
        &self,
    ) -> Result<IndexSet<ExternalFile>, Self::Error> {
        use sos_reducers::FileReducer;
        let files = self.file_log().await?;
        let event_log = files.read().await;

        // Canonical list of external files.
        let reducer = FileReducer::new(&*event_log);
        Ok(reducer.reduce(None).await?)
    }

    /// Folders managed by this storage.
    ///
    /// Built from the in-memory list of folders.
    async fn folder_details(&self) -> Result<IndexSet<Summary>, Self::Error>;

    /// Folder event log.
    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>, Self::Error>;
}

/// Types that can merge diffs.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Merge: StorageEventLogs {
    /// Merge changes to the identity folder.
    async fn merge_identity(
        &mut self,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> std::result::Result<CheckedPatch, Self::Error>;

    /// Compare the identity folder.
    async fn compare_identity(
        &self,
        state: &CommitState,
    ) -> std::result::Result<Comparison, Self::Error> {
        let log = self.identity_log().await?;
        let event_log = log.read().await;
        Ok(event_log.tree().compare(&state.1)?)
    }

    /// Merge changes to the account event log.
    async fn merge_account(
        &mut self,
        diff: AccountDiff,
        outcome: &mut MergeOutcome,
    ) -> std::result::Result<(CheckedPatch, HashSet<VaultId>), Self::Error>;

    /// Compare the account events.
    async fn compare_account(
        &self,
        state: &CommitState,
    ) -> std::result::Result<Comparison, Self::Error> {
        let log = self.account_log().await?;
        let event_log = log.read().await;
        Ok(event_log.tree().compare(&state.1)?)
    }

    /// Merge changes to the devices event log.
    async fn merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> std::result::Result<CheckedPatch, Self::Error>;

    /// Compare the device events.
    async fn compare_device(
        &self,
        state: &CommitState,
    ) -> std::result::Result<Comparison, Self::Error> {
        let log = self.device_log().await?;
        let event_log = log.read().await;
        Ok(event_log.tree().compare(&state.1)?)
    }

    /// Merge changes to the files event log.
    #[cfg(feature = "files")]
    async fn merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> std::result::Result<CheckedPatch, Self::Error>;

    /// Compare the file events.
    #[cfg(feature = "files")]
    async fn compare_files(
        &self,
        state: &CommitState,
    ) -> std::result::Result<Comparison, Self::Error> {
        let log = self.file_log().await?;
        let event_log = log.read().await;
        Ok(event_log.tree().compare(&state.1)?)
    }

    /// Merge changes to a folder.
    async fn merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> std::result::Result<(CheckedPatch, Vec<WriteEvent>), Self::Error>;

    /// Compare folder events.
    async fn compare_folder(
        &self,
        folder_id: &VaultId,
        state: &CommitState,
    ) -> std::result::Result<Comparison, Self::Error> {
        let event_log = self.folder_log(folder_id).await?;
        let reader = event_log.read().await;
        Ok(reader.tree().compare(&state.1)?)
    }

    /// Compare the local state to a remote status.
    async fn compare(
        &mut self,
        remote_status: &SyncStatus,
    ) -> std::result::Result<SyncCompare, Self::Error> {
        let mut compare = SyncCompare::default();

        compare.identity =
            Some(self.compare_identity(&remote_status.identity).await?);

        compare.account =
            Some(self.compare_account(&remote_status.account).await?);

        compare.device =
            Some(self.compare_device(&remote_status.device).await?);

        #[cfg(feature = "files")]
        if let Some(files) = &remote_status.files {
            compare.files = Some(self.compare_files(files).await?);
        }

        for (id, folder_status) in &remote_status.folders {
            compare
                .folders
                .insert(*id, self.compare_folder(id, folder_status).await?);
        }

        Ok(compare)
    }

    /// Merge a diff into this storage.
    async fn merge(
        &mut self,
        diff: SyncDiff,
        outcome: &mut MergeOutcome,
    ) -> std::result::Result<SyncCompare, Self::Error> {
        let mut compare = SyncCompare::default();

        match diff.identity {
            Some(MaybeDiff::Diff(diff)) => {
                self.merge_identity(diff, outcome).await?;
            }
            Some(MaybeDiff::Compare(Some(state))) => {
                compare.identity =
                    Some(self.compare_identity(&state).await?);
            }
            Some(MaybeDiff::Compare(None)) => {}
            None => {}
        }

        let mut deleted_folders = HashSet::new();

        match diff.account {
            Some(MaybeDiff::Diff(diff)) => {
                let (_, deletions) =
                    self.merge_account(diff, outcome).await?;
                deleted_folders = deletions;
            }
            Some(MaybeDiff::Compare(state)) => {
                if let Some(state) = state {
                    compare.account =
                        Some(self.compare_account(&state).await?);
                }
            }
            None => {}
        }

        match diff.device {
            Some(MaybeDiff::Diff(diff)) => {
                self.merge_device(diff, outcome).await?;
            }
            Some(MaybeDiff::Compare(state)) => {
                if let Some(state) = state {
                    compare.device = Some(self.compare_device(&state).await?);
                }
            }
            None => {}
        }

        #[cfg(feature = "files")]
        match diff.files {
            Some(MaybeDiff::Diff(diff)) => {
                self.merge_files(diff, outcome).await?;
            }
            Some(MaybeDiff::Compare(state)) => {
                if let Some(state) = state {
                    compare.files = Some(self.compare_files(&state).await?);
                }
            }
            None => {}
        }

        for (id, maybe_diff) in diff.folders {
            // Don't bother trying to merge folders that
            // have been deleted
            if deleted_folders.contains(&id) {
                tracing::debug!(
                    folder_id = %id,
                    "merge::ignore_deleted_folder");
                continue;
            }
            match maybe_diff {
                MaybeDiff::Diff(diff) => {
                    self.merge_folder(&id, diff, outcome).await?;
                }
                MaybeDiff::Compare(state) => {
                    if let Some(state) = state {
                        compare.folders.insert(
                            id,
                            self.compare_folder(&id, &state).await?,
                        );
                    }
                }
            }
        }

        tracing::debug!(num_changes = %outcome.changes, "merge complete");

        Ok(compare)
    }
}

/// Types that can force merge a diff.
///
/// Force merge deletes all events from the log and
/// applies the diff patch as a new set of events.
///
/// Use this when event logs have completely diverged
/// and need to be rewritten.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ForceMerge: Merge {
    /// Force merge from a set of updates.
    ///
    /// Update an account from a change set of event diffs.
    ///
    /// Overwrites all existing account data with the event logs
    /// in the change set.
    ///
    /// Intended to be used to perform a destructive overwrite
    /// when changing the encryption cipher or other events
    /// which rewrite the account data.
    async fn force_merge_update(
        &mut self,
        mut update_set: UpdateSet,
        outcome: &mut MergeOutcome,
    ) -> std::result::Result<(), Self::Error> {
        if let Some(diff) = update_set.identity.take() {
            self.force_merge_identity(diff, outcome).await?;
        }

        if let Some(diff) = update_set.account.take() {
            self.force_merge_account(diff, outcome).await?;
        }

        if let Some(diff) = update_set.device.take() {
            self.force_merge_device(diff, outcome).await?;
        }

        #[cfg(feature = "files")]
        if let Some(diff) = update_set.files.take() {
            self.force_merge_files(diff, outcome).await?;
        }

        for (id, folder) in update_set.folders {
            self.force_merge_folder(&id, folder, outcome).await?;
        }
        Ok(())
    }

    /// Force merge changes to the identity folder.
    async fn force_merge_identity(
        &mut self,
        source: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> std::result::Result<(), Self::Error>;

    /// Force merge changes to the account event log.
    async fn force_merge_account(
        &mut self,
        diff: AccountDiff,
        outcome: &mut MergeOutcome,
    ) -> std::result::Result<(), Self::Error> {
        let len = diff.patch.len() as u64;

        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = len,
            "force_merge::account",
        );

        let event_log = self.account_log().await?;
        let mut event_log = event_log.write().await;
        event_log.replace_all_events(&diff).await?;

        outcome.changes += len;
        outcome.tracked.account =
            TrackedChanges::new_account_records(&diff.patch).await?;

        Ok(())
    }

    /// Force merge changes to the devices event log.
    async fn force_merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> std::result::Result<(), Self::Error> {
        let len = diff.patch.len() as u64;

        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = len,
            "force_merge::device",
        );

        let event_log = self.device_log().await?;
        let mut event_log = event_log.write().await;
        event_log.replace_all_events(&diff).await?;

        outcome.changes += len;
        outcome.tracked.device =
            TrackedChanges::new_device_records(&diff.patch).await?;

        Ok(())
    }

    /// Force merge changes to the files event log.
    #[cfg(feature = "files")]
    async fn force_merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> std::result::Result<(), Self::Error> {
        let len = diff.patch.len() as u64;

        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = len,
            "force_merge::files",
        );

        let event_log = self.file_log().await?;
        let mut event_log = event_log.write().await;
        event_log.replace_all_events(&diff).await?;

        outcome.changes += len;
        outcome.tracked.files =
            TrackedChanges::new_file_records(&diff.patch).await?;

        Ok(())
    }

    /// Force merge changes to a folder.
    async fn force_merge_folder(
        &mut self,
        folder_id: &VaultId,
        source: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> std::result::Result<(), Self::Error>;
}

/// Storage implementations that can synchronize.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait SyncStorage: ForceMerge {
    /// Determine if this is client-side storage.
    fn is_client_storage(&self) -> bool;

    /// Sync status for the storage.
    async fn sync_status(
        &self,
    ) -> std::result::Result<SyncStatus, Self::Error> {
        // NOTE: the order for computing the cumulative
        // NOTE: root hash must be identical to the logic
        // NOTE: in the server implementation and the folders
        // NOTE: collection must be sorted so that the folders
        // NOTE: root hash is deterministic

        let summaries = self.folder_details().await?;

        let identity = {
            let event_log = self.identity_log().await?;
            let reader = event_log.read().await;
            reader.tree().commit_state()?
        };

        let account = {
            let event_log = self.account_log().await?;
            let reader = event_log.read().await;
            reader.tree().commit_state()?
        };

        let device = {
            let event_log = self.device_log().await?;
            let reader = event_log.read().await;
            reader.tree().commit_state()?
        };

        #[cfg(feature = "files")]
        let files = {
            let event_log = self.file_log().await?;
            let reader = event_log.read().await;
            if reader.tree().is_empty() {
                None
            } else {
                Some(reader.tree().commit_state()?)
            }
        };

        let mut folders = IndexMap::new();
        let mut folder_roots: Vec<(&VaultId, [u8; 32])> = Vec::new();
        for summary in &summaries {
            let event_log = self.folder_log(summary.id()).await?;
            let reader = event_log.read().await;
            let commit_state = reader.tree().commit_state()?;
            folder_roots.push((summary.id(), commit_state.1.root().into()));
            folders.insert(*summary.id(), commit_state);
        }

        // Compute a root hash of all the trees for an account
        let mut root_tree = CommitTree::new();
        let mut root_commits = vec![
            identity.1.root().into(),
            account.1.root().into(),
            device.1.root().into(),
        ];
        #[cfg(feature = "files")]
        if let Some(files) = &files {
            root_commits.push(files.1.root().into());
        }

        folder_roots.sort_by(|a, b| a.0.cmp(b.0));
        let mut folder_roots =
            folder_roots.into_iter().map(|f| f.1).collect::<Vec<_>>();
        root_commits.append(&mut folder_roots);
        root_tree.append(&mut root_commits);
        root_tree.commit();

        let root = root_tree.root().ok_or(sos_core::Error::NoRootCommit)?;

        Ok(SyncStatus {
            root,
            identity,
            account,
            device,
            #[cfg(feature = "files")]
            files,
            folders,
        })
    }

    /// Set of all event logs.
    ///
    /// Used by network aware implementations to transfer
    /// entire accounts.
    async fn create_set(
        &self,
    ) -> std::result::Result<CreateSet, Self::Error> {
        let identity = {
            let log = self.identity_log().await?;
            let reader = log.read().await;
            reader.diff_events(None).await?
        };

        let account = {
            let log = self.account_log().await?;
            let reader = log.read().await;
            reader.diff_events(None).await?
        };

        let device = {
            let log = self.device_log().await?;
            let reader = log.read().await;
            reader.diff_events(None).await?
        };

        #[cfg(feature = "files")]
        let files = {
            let log = self.file_log().await?;
            let reader = log.read().await;
            reader.diff_events(None).await?
        };

        let mut folders = HashMap::new();
        let details = self.folder_details().await?;

        for folder in details {
            if folder.flags().is_sync_disabled() {
                tracing::debug!(
                    folder_id = %folder.id(),
                    "create_set::ignore::no_sync_flag");
                continue;
            }
            let event_log = self.folder_log(folder.id()).await?;
            let log_file = event_log.read().await;
            folders.insert(*folder.id(), log_file.diff_events(None).await?);
        }

        Ok(CreateSet {
            identity,
            account,
            folders,
            device,
            #[cfg(feature = "files")]
            files,
        })
    }

    /// Create a debug tree of this account.
    async fn debug_account_tree(
        &self,
        account_id: AccountId,
    ) -> Result<DebugTree, Self::Error> {
        let status = self.sync_status().await?;

        // Redact folder names
        let folder_list = {
            let mut folder_list = self.folder_details().await?;
            let mut redacted = IndexSet::new();
            for mut folder in folder_list.drain(..) {
                folder.set_name(String::new());
                redacted.insert(folder);
            }
            redacted
        };

        let identity = {
            let event_log = self.identity_log().await?;
            let event_log = event_log.read().await;
            debug_tree_events!(&*event_log)
        };

        let account = {
            let event_log = self.account_log().await?;
            let event_log = event_log.read().await;
            debug_tree_events!(&*event_log)
        };

        let device = {
            let event_log = self.device_log().await?;
            let event_log = event_log.read().await;
            debug_tree_events!(&*event_log)
        };

        #[cfg(feature = "files")]
        let file = {
            let event_log = self.file_log().await?;
            let event_log = event_log.read().await;
            debug_tree_events!(&*event_log)
        };

        let folders = {
            let mut folders = HashMap::new();
            for summary in &folder_list {
                let event_log = self.folder_log(summary.id()).await?;
                let event_log = event_log.read().await;
                folders
                    .insert(*summary.id(), debug_tree_events!(&*event_log));
            }
            folders
        };

        Ok(DebugTree {
            account_id,
            status,
            folders: folder_list,
            events: DebugEventLogs {
                identity,
                account,
                device,
                #[cfg(feature = "files")]
                file,
                folders,
            },
        })
    }
}
