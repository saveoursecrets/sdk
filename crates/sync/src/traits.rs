//! Core traits for storage that supports synchronization.
use crate::{
    CreateSet, MaybeDiff, MergeOutcome, SyncCompare, SyncDiff, SyncStatus,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_core::{
    commit::{CommitState, Comparison},
    VaultId,
};
use sos_sdk::{
    events::{
        AccountDiff, AccountEventLog, CheckedPatch, DeviceDiff,
        DeviceEventLog, EventLogExt, FolderDiff, FolderEventLog, WriteEvent,
    },
    vault::Summary,
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;

#[cfg(feature = "files")]
use {
    sos_core::ExternalFile,
    sos_sdk::events::{FileDiff, FileEventLog},
};

/// References to the storage event logs.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait StorageEventLogs {
    /// Error type for storage event logs.
    type Error: std::error::Error
        + From<sos_core::Error>
        + From<sos_sdk::Error>
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
        use sos_sdk::events::FileReducer;
        let files = self.file_log().await?;
        let event_log = files.read().await;

        // Canonical list of external files.
        let reducer = FileReducer::new(&event_log);
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
    ) -> std::result::Result<Comparison, Self::Error>;

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
    ) -> std::result::Result<Comparison, Self::Error>;

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
    ) -> std::result::Result<Comparison, Self::Error>;

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
    ) -> std::result::Result<Comparison, Self::Error>;

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
    ) -> std::result::Result<Comparison, Self::Error>;

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
            Some(MaybeDiff::Compare(state)) => {
                if let Some(state) = state {
                    compare.identity =
                        Some(self.compare_identity(&state).await?);
                }
            }
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
pub trait ForceMerge: StorageEventLogs {
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
    ) -> std::result::Result<(), Self::Error>;

    /// Force merge changes to the devices event log.
    async fn force_merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> std::result::Result<(), Self::Error>;

    /// Force merge changes to the files event log.
    #[cfg(feature = "files")]
    async fn force_merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> std::result::Result<(), Self::Error>;

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
pub trait SyncStorage: StorageEventLogs {
    /// Determine if this is client-side storage.
    fn is_client_storage(&self) -> bool;

    /// Get the sync status.
    async fn sync_status(
        &self,
    ) -> std::result::Result<SyncStatus, Self::Error>;

    /// Change set of all event logs.
    ///
    /// Used by network aware implementations to transfer
    /// entire accounts.
    async fn change_set(
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
                    "change_set::ignore::no_sync_flag");
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
}
