//! Synchronization types that are used internally.
use crate::sdk::{
    commit::{CommitState, Comparison},
    events::{
        AccountDiff, CheckedPatch, EventLogExt, FolderDiff, WriteEvent,
    },
    storage::StorageEventLogs,
    vault::VaultId,
    Error, Result,
};
use crate::{
    CreateSet, MaybeDiff, MergeOutcome, Origin, SyncCompare, SyncDiff,
    SyncStatus,
};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};

use crate::sdk::events::DeviceDiff;

#[cfg(feature = "files")]
use crate::sdk::events::FileDiff;

/// How to resolve hard conflicts.
#[derive(Default, Debug)]
pub enum HardConflictResolver {
    /// Automatically fetch and overwrite account data.
    #[default]
    AutomaticFetch,
}

/// Options for sync operation.
#[derive(Default, Debug)]
pub struct SyncOptions {
    /// Only sync these origins.
    pub origins: Vec<Origin>,
    /// Resolver for hard conflicts.
    pub hard_conflict_resolver: HardConflictResolver,
}

/// Options for folder merge.
pub(crate) enum FolderMergeOptions<'a> {
    /// Update a URN lookup when merging.
    Urn(VaultId, &'a mut crate::sdk::identity::UrnLookup),
    /// Update a search index when merging.
    #[cfg(feature = "search")]
    Search(VaultId, &'a mut crate::sdk::storage::search::SearchIndex),
}

/*
impl FolderMergeOptions<'_> {
    /// Folder identifier.
    pub fn folder_id(&self) -> &VaultId {
        match self {
            Self::Urn(id, _) => id,
            Self::Search(id, _) => id,
        }
    }
}
*/

/// Information about possible conflicts.
#[derive(Debug, Default, Eq, PartialEq)]
pub struct MaybeConflict {
    /// Whether the identity folder might be conflicted.
    pub identity: bool,
    /// Whether the account log might be conflicted.
    pub account: bool,
    /// Whether the device log might be conflicted.
    pub device: bool,
    /// Whether the files log might be conflicted.
    #[cfg(feature = "files")]
    pub files: bool,
    /// Account folders that might be conflicted.
    pub folders: IndexMap<VaultId, bool>,
}

impl MaybeConflict {
    /// Check for any conflicts.
    pub fn has_conflicts(&self) -> bool {
        let mut has_conflicts = self.identity || self.account || self.device;

        #[cfg(feature = "files")]
        {
            has_conflicts = has_conflicts || self.files;
        }

        for (_, value) in &self.folders {
            has_conflicts = has_conflicts || *value;
            if has_conflicts {
                break;
            }
        }

        has_conflicts
    }
}

/// Comparison between local and remote status.
#[derive(Debug)]
pub struct SyncComparison {
    /// Local sync status.
    pub local_status: SyncStatus,
    /// Remote sync status.
    pub remote_status: SyncStatus,
    /// Comparison of the identity event log.
    pub identity: Comparison,
    /// Comparison of the account event log.
    pub account: Comparison,
    /// Comparison of the device event log.
    pub device: Comparison,
    /// Comparison of the files event log.
    #[cfg(feature = "files")]
    pub files: Option<Comparison>,
    /// Comparison for each folder in the account.
    pub folders: IndexMap<VaultId, Comparison>,
}

impl SyncComparison {
    /// Create a new sync comparison.
    pub async fn new(
        storage: &impl SyncStorage,
        remote_status: SyncStatus,
    ) -> Result<SyncComparison> {
        let local_status = storage.sync_status().await?;

        let identity = {
            let identity = storage.identity_log().await?;
            let reader = identity.read().await;
            reader.tree().compare(&remote_status.identity.1)?
        };

        let account = {
            let account = storage.account_log().await?;
            let reader = account.read().await;
            reader.tree().compare(&remote_status.account.1)?
        };

        let device = {
            let device = storage.device_log().await?;
            let reader = device.read().await;
            reader.tree().compare(&remote_status.device.1)?
        };

        #[cfg(feature = "files")]
        let files = {
            let files = storage.file_log().await?;
            let reader = files.read().await;
            if let Some(files) = &remote_status.files {
                if reader.tree().is_empty() {
                    None
                } else {
                    Some(reader.tree().compare(&files.1)?)
                }
            } else if reader.tree().is_empty() {
                None
            } else {
                Some(Comparison::Unknown)
            }
        };

        let folders = {
            let mut folders = IndexMap::new();
            for (id, folder) in &remote_status.folders {
                // Folder may exist on remote but not locally
                // if we have just deleted a folder
                if let Ok(event_log) = storage.folder_log(id).await {
                    let event_log = event_log.read().await;
                    folders.insert(*id, event_log.tree().compare(&folder.1)?);
                }
            }

            folders
        };

        Ok(SyncComparison {
            local_status,
            remote_status,
            identity,
            account,
            device,
            #[cfg(feature = "files")]
            files,
            folders,
        })
    }

    /// Determine if synchronization is required.
    pub fn needs_sync(&self) -> bool {
        self.local_status != self.remote_status
    }

    /// Build a diff from this comparison.
    ///
    /// The diff includes changes on local that are not yet
    /// present on the remote or information that will allow
    /// a comparison on the remote.
    pub async fn diff<S>(&self, storage: &S) -> Result<SyncDiff>
    where
        S: SyncStorage,
    {
        let mut diff: SyncDiff = Default::default();

        match self.identity {
            Comparison::Equal => {}
            Comparison::Contains(_) => {
                // Need to push changes to remote
                let log = storage.identity_log().await?;
                let reader = log.read().await;
                let is_last_commit = Some(&self.remote_status.identity.0)
                    == reader.tree().last_commit().as_ref();

                // Avoid empty patches when commit is already the last
                if !is_last_commit {
                    let identity = reader
                        .diff_checked(
                            Some(self.remote_status.identity.0),
                            self.remote_status.identity.1.clone(),
                        )
                        .await?;
                    diff.identity = Some(MaybeDiff::Diff(identity));
                }
            }
            Comparison::Unknown => {
                tracing::info!(
                    local = ?self.local_status.identity,
                    remote = ?self.remote_status.identity,
                    "identity folder divergence"
                );

                diff.identity = Some(MaybeDiff::Compare(Some(
                    self.local_status.identity.clone(),
                )));
            }
        }

        match self.account {
            Comparison::Equal => {}
            Comparison::Contains(_) => {
                // Need to push changes to remote
                let log = storage.account_log().await?;
                let reader = log.read().await;

                let is_last_commit = Some(&self.remote_status.account.0)
                    == reader.tree().last_commit().as_ref();

                // Avoid empty patches when commit is already the last
                if !is_last_commit {
                    let account = reader
                        .diff_checked(
                            Some(self.remote_status.account.0),
                            self.remote_status.account.1.clone(),
                        )
                        .await?;
                    diff.account = Some(MaybeDiff::Diff(account));
                }
            }
            Comparison::Unknown => {
                tracing::info!(
                    local = ?self.local_status.account,
                    remote = ?self.remote_status.account,
                    "account events divergence"
                );

                diff.account = Some(MaybeDiff::Compare(Some(
                    self.local_status.account.clone(),
                )));
            }
        }

        match self.device {
            Comparison::Equal => {}
            Comparison::Contains(_) => {
                // Need to push changes to remote
                let log = storage.device_log().await?;
                let reader = log.read().await;

                let is_last_commit = Some(&self.remote_status.device.0)
                    == reader.tree().last_commit().as_ref();

                // Avoid empty patches when commit is already the last
                if !is_last_commit {
                    let device = reader
                        .diff_checked(
                            Some(self.remote_status.device.0),
                            self.remote_status.device.1.clone(),
                        )
                        .await?;
                    diff.device = Some(MaybeDiff::Diff(device));
                }
            }
            Comparison::Unknown => {
                tracing::info!(
                    local = ?self.local_status.device,
                    remote = ?self.remote_status.device,
                    "device events divergence"
                );

                // NOTE: this will break the device revoke test spec!
                /*
                diff.device = Some(MaybeDiff::Compare(Some(
                    self.local_status.device.clone(),
                )));
                */
            }
        }

        #[cfg(feature = "files")]
        match (&self.files, &self.remote_status.files) {
            (Some(files), Some(remote_files)) => {
                match files {
                    Comparison::Equal => {}
                    Comparison::Contains(_) => {
                        // Need to push changes to remote
                        let log = storage.file_log().await?;
                        let reader = log.read().await;

                        let is_last_commit = Some(&remote_files.0)
                            == reader.tree().last_commit().as_ref();

                        // Avoid empty patches when commit is already the last
                        if !is_last_commit {
                            let files = reader
                                .diff_checked(
                                    Some(remote_files.0),
                                    remote_files.1.clone(),
                                )
                                .await?;

                            diff.files = Some(MaybeDiff::Diff(files));
                        }
                    }
                    Comparison::Unknown => {
                        tracing::info!(
                            local = ?files,
                            remote = ?remote_files,
                            "file events divergence"
                        );

                        diff.files = Some(MaybeDiff::Compare(
                            self.local_status.files.clone(),
                        ));
                    }
                }
            }
            // Remote does not have any files yet so we need
            // to send the entire file event log
            (Some(Comparison::Unknown), None) => {
                // Need to push changes to remote
                let log = storage.file_log().await?;
                let reader = log.read().await;
                if !reader.tree().is_empty() {
                    let files = FileDiff {
                        last_commit: None,
                        patch: reader.diff_events(None).await?,
                        checkpoint: Default::default(),
                    };
                    diff.files = Some(MaybeDiff::Diff(files));
                }
            }
            _ => {}
        }

        for (id, folder) in &self.folders {
            let commit_state = self
                .remote_status
                .folders
                .get(id)
                .ok_or(Error::CacheNotAvailable(*id))?;

            match folder {
                Comparison::Equal => {}
                Comparison::Contains(_) => {
                    // Need to push changes to remote
                    let log = storage.folder_log(id).await?;
                    let log = log.read().await;
                    let folder = log
                        .diff_checked(
                            Some(commit_state.0),
                            commit_state.1.clone(),
                        )
                        .await?;

                    if !folder.patch.is_empty() {
                        diff.folders.insert(*id, MaybeDiff::Diff(folder));
                    }
                }
                Comparison::Unknown => {
                    tracing::info!(
                        id = %id,
                        local = ?self.local_status.folders.get(id),
                        remote = ?commit_state,
                        "folder events divergence"
                    );

                    diff.folders.insert(
                        *id,
                        MaybeDiff::Compare(
                            self.local_status.folders.get(id).cloned(),
                        ),
                    );
                }
            }
        }

        // Handle events for new folders on local that
        // don't exist on remote yet
        for (id, _) in &self.local_status.folders {
            if self.remote_status.folders.get(id).is_none() {
                let log = storage.folder_log(id).await?;
                let log = log.read().await;
                let first_commit = log.tree().first_commit()?;

                let folder = FolderDiff {
                    last_commit: Some(first_commit.0),
                    patch: log.diff_events(Some(&first_commit.0)).await?,
                    checkpoint: first_commit.1,
                };

                if !folder.patch.is_empty() {
                    diff.folders.insert(*id, MaybeDiff::Diff(folder));
                }
            }
        }

        Ok(diff)
    }
}

/// Storage implementations that can synchronize.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait SyncStorage: StorageEventLogs {
    /// Determine if this is client-side storage.
    fn is_client_storage(&self) -> bool;

    /// Get the sync status.
    async fn sync_status(&self) -> Result<SyncStatus>;

    /// Change set of all event logs.
    ///
    /// Used by network aware implementations to transfer
    /// entire accounts.
    async fn change_set(&self) -> Result<CreateSet> {
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

/// Types that can force merge a diff.
///
/// Force merge deletes all events from the log and
/// applies the diff patch as a new set of events.
///
/// Use this when event logs have completely diverged
/// and need to be rewritten.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ForceMerge {
    /// Force merge changes to the identity folder.
    async fn force_merge_identity(
        &mut self,
        source: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()>;

    /// Force merge changes to the account event log.
    async fn force_merge_account(
        &mut self,
        diff: AccountDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()>;

    /// Force merge changes to the devices event log.
    async fn force_merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()>;

    /// Force merge changes to the files event log.
    #[cfg(feature = "files")]
    async fn force_merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()>;

    /// Force merge changes to a folder.
    async fn force_merge_folder(
        &mut self,
        folder_id: &VaultId,
        source: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()>;
}

/// Types that can merge diffs.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Merge {
    /// Merge changes to the identity folder.
    async fn merge_identity(
        &mut self,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch>;

    /// Compare the identity folder.
    async fn compare_identity(
        &self,
        state: &CommitState,
    ) -> Result<Comparison>;

    /// Merge changes to the account event log.
    async fn merge_account(
        &mut self,
        diff: AccountDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<(CheckedPatch, HashSet<VaultId>)>;

    /// Compare the account events.
    async fn compare_account(
        &self,
        state: &CommitState,
    ) -> Result<Comparison>;

    /// Merge changes to the devices event log.
    async fn merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch>;

    /// Compare the device events.
    async fn compare_device(&self, state: &CommitState)
        -> Result<Comparison>;

    /// Merge changes to the files event log.
    #[cfg(feature = "files")]
    async fn merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch>;

    /// Compare the file events.
    #[cfg(feature = "files")]
    async fn compare_files(&self, state: &CommitState) -> Result<Comparison>;

    /// Merge changes to a folder.
    async fn merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<(CheckedPatch, Vec<WriteEvent>)>;

    /// Compare folder events.
    async fn compare_folder(
        &self,
        folder_id: &VaultId,
        state: &CommitState,
    ) -> Result<Comparison>;

    /// Compare the local state to a remote status.
    async fn compare(
        &mut self,
        remote_status: &SyncStatus,
    ) -> Result<SyncCompare> {
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
    ) -> Result<SyncCompare> {
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

/// Difference between a local sync status and a remote
/// sync status.
pub async fn diff(
    storage: &(impl SyncStorage + Send + Sync),
    remote_status: SyncStatus,
) -> Result<(bool, SyncStatus, SyncDiff)> {
    let comparison = {
        // Compare local status to the remote
        SyncComparison::new(storage, remote_status).await?
    };

    let needs_sync = comparison.needs_sync();
    let mut diff = comparison.diff(storage).await?;

    let is_server = !storage.is_client_storage();
    if is_server {
        let storage_folders = storage.folder_details().await?;
        diff.folders.retain(|k, _| {
            if let Some(folder) = storage_folders.iter().find(|s| s.id() == k)
            {
                !folder.flags().is_sync_disabled()
            } else {
                true
            }
        });
    }

    Ok((needs_sync, comparison.local_status, diff))
}
