//! Synchronization primitives.
use crate::{
    commit::{CommitHash, CommitProof, CommitState, Comparison},
    events::{AccountEvent, EventLogExt, WriteEvent},
    storage::{files::ExternalFile, StorageEventLogs},
    vault::VaultId,
    Error, Result,
};
use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    hash::{Hash, Hasher},
};
use url::Url;

mod patch;
pub use patch::{AccountPatch, FolderPatch, Patch};

#[cfg(feature = "device")]
use crate::events::DeviceEvent;

#[cfg(feature = "device")]
pub use patch::DevicePatch;

#[cfg(feature = "files")]
use crate::events::FileEvent;

#[cfg(feature = "files")]
pub use patch::FilePatch;

/// Server origin information.
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct Origin {
    name: String,
    url: Url,
}

impl Origin {
    /// Create a new origin.
    pub fn new(name: String, url: Url) -> Self {
        Self { name, url }
    }

    /// Name of the origin server.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// URL of the origin server.
    pub fn url(&self) -> &Url {
        &self.url
    }
}

impl PartialEq for Origin {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl Hash for Origin {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.url.hash(state);
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.url)
    }
}

impl From<Url> for Origin {
    fn from(url: Url) -> Self {
        let name = url.authority().to_owned();
        Self { name, url }
    }
}

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

/// Error type that can be returned from a sync operation.
#[derive(Debug)]
pub struct SyncError<T: std::error::Error> {
    /// Errors generated during a sync operation.
    pub errors: Vec<(Origin, T)>,
}

impl<T: std::error::Error> fmt::Display for SyncError<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (_, e) in self.errors.iter() {
            write!(f, "{}", e)?;
        }
        Ok(())
    }
}

impl<T: std::error::Error> SyncError<T> {
    /// Convert to an option.
    pub fn into_option(self) -> Option<Self> {
        if self.errors.is_empty() {
            None
        } else {
            Some(self)
        }
    }
}

impl<T: std::error::Error> Default for SyncError<T> {
    fn default() -> Self {
        Self { errors: Vec::new() }
    }
}

/// Options for folder merge.
#[derive(Default)]
pub(crate) enum FolderMergeOptions<'a> {
    #[doc(hidden)]
    #[default]
    Noop,
    /// Update a URN lookup when merging.
    Urn(VaultId, &'a mut crate::identity::UrnLookup),
    /// Update a search index when merging.
    #[cfg(feature = "search")]
    Search(VaultId, &'a mut crate::storage::search::SearchIndex),
}

/// Result of a checked patch on an event log.
#[derive(Default, Debug)]
pub enum CheckedPatch {
    #[doc(hidden)]
    #[default]
    Noop,
    /// Patch was applied.
    Success(CommitProof),
    /// Patch conflict.
    Conflict {
        /// Head of the event log.
        head: CommitProof,
        /// If the checked proof is contained
        /// in the event log.
        contains: Option<CommitProof>,
    },
}

/// Diff between local and remote.
#[derive(Default, Debug, Clone)]
pub struct Diff<T> {
    /// Last commit hash before the patch was created.
    ///
    /// This can be used to determine if the patch is to
    /// be used to initialize a new set of events when
    /// no last commit is available.
    ///
    /// For example, for file event logs which are
    /// lazily instantiated once external files are created.
    pub last_commit: Option<CommitHash>,

    /// Contents of the patch.
    pub patch: Patch<T>,
    /// Checkpoint for the diff patch.
    ///
    /// For checked patches this must match the proof
    /// of HEAD before the patch was created.
    ///
    /// For unchecked force merges this checkpoint
    /// references the commit proof of HEAD after
    /// applying the patch.
    pub checkpoint: CommitProof,
}

/// Diff between account events logs.
pub type AccountDiff = Diff<AccountEvent>;

/// Diff between device events logs.
#[cfg(feature = "device")]
pub type DeviceDiff = Diff<DeviceEvent>;

/// Diff between file events logs.
#[cfg(feature = "files")]
pub type FileDiff = Diff<FileEvent>;

/// Diff between folder events logs.
pub type FolderDiff = Diff<WriteEvent>;

/// Combined sync status, diff and comparisons.
#[derive(Debug, Default, Clone)]
pub struct SyncPacket {
    /// Sync status.
    pub status: SyncStatus,
    /// Sync diff.
    pub diff: SyncDiff,
    /// Sync comparisons.
    pub compare: Option<SyncCompare>,
}

/// Provides a status overview of an account.
///
/// Intended to be used during a synchronization protocol.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct SyncStatus {
    /// Computed root of all event log roots.
    pub root: CommitHash,
    /// Identity vault commit state.
    pub identity: CommitState,
    /// Account log commit state.
    pub account: CommitState,
    /// Device log commit state.
    #[cfg(feature = "device")]
    pub device: CommitState,
    /// Files log commit state.
    #[cfg(feature = "files")]
    pub files: Option<CommitState>,
    /// Commit proofs for the account folders.
    pub folders: IndexMap<VaultId, CommitState>,
}

/// Collection of comparisons for an account.
///
/// When a local account does not contain the proof for
/// a remote event log if will interrogate the server to
/// compare it's proof with the remote tree.
///
/// The server will reply with comparison(s) so that the local
/// account can determine if the trees have completely diverged
/// or whether it can attempt to automatically merge
/// partially diverged trees.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct SyncCompare {
    /// Identity vault comparison.
    pub identity: Option<Comparison>,
    /// Account log comparison.
    pub account: Option<Comparison>,
    /// Device log comparison.
    #[cfg(feature = "device")]
    pub device: Option<Comparison>,
    /// Files log comparison.
    #[cfg(feature = "files")]
    pub files: Option<Comparison>,
    /// Comparisons for the account folders.
    pub folders: IndexMap<VaultId, Comparison>,
}

impl SyncCompare {
    /// Determine if this comparison might conflict.
    pub fn maybe_conflict(&self) -> MaybeConflict {
        MaybeConflict {
            identity: self
                .identity
                .as_ref()
                .map(|c| matches!(c, Comparison::Unknown))
                .unwrap_or(false),
            account: self
                .account
                .as_ref()
                .map(|c| matches!(c, Comparison::Unknown))
                .unwrap_or(false),
            #[cfg(feature = "device")]
            device: self
                .device
                .as_ref()
                .map(|c| matches!(c, Comparison::Unknown))
                .unwrap_or(false),
            #[cfg(feature = "files")]
            files: self
                .files
                .as_ref()
                .map(|c| matches!(c, Comparison::Unknown))
                .unwrap_or(false),
            folders: self
                .folders
                .iter()
                .map(|(k, v)| (*k, matches!(v, Comparison::Unknown)))
                .collect(),
        }
    }
}

/// Information about possible conflicts.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct MaybeConflict {
    /// Whether the identity folder might be conflicted.
    pub identity: bool,
    /// Whether the account log might be conflicted.
    pub account: bool,
    /// Whether the device log might be conflicted.
    #[cfg(feature = "device")]
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
        let mut has_conflicts = self.identity || self.account;

        #[cfg(feature = "device")]
        {
            has_conflicts = has_conflicts || self.device;
        }

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

/// Diff of events or conflict information.
#[derive(Default, Debug, Clone)]
pub enum MaybeDiff<T> {
    #[doc(hidden)]
    #[default]
    Noop,
    /// Diff of local changes to send to the remote.
    Diff(T),
    /// Local needs to compare it's state with remote.
    // The additional `Option` wrapper is required because
    // the files event log may not exist.
    Compare(Option<CommitState>),
}

/// Diff between all events logs on local and remote.
#[derive(Default, Debug, Clone)]
pub struct SyncDiff {
    /// Diff of the identity vault event logs.
    pub identity: Option<MaybeDiff<FolderDiff>>,
    /// Diff of the account event log.
    pub account: Option<MaybeDiff<AccountDiff>>,
    /// Diff of the device event log.
    #[cfg(feature = "device")]
    pub device: Option<MaybeDiff<DeviceDiff>>,
    /// Diff of the files event log.
    #[cfg(feature = "files")]
    pub files: Option<MaybeDiff<FileDiff>>,
    /// Diff for folders in the account.
    pub folders: IndexMap<VaultId, MaybeDiff<FolderDiff>>,
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
    #[cfg(feature = "device")]
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

        #[cfg(feature = "device")]
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
            #[cfg(feature = "device")]
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
    pub async fn diff(&self, storage: &impl SyncStorage) -> Result<SyncDiff> {
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
                    /*
                    let identity = FolderDiff {
                        last_commit: Some(self.remote_status.identity.0),
                        patch: reader
                            .diff(Some(&self.remote_status.identity.0))
                            .await?,
                        checkpoint: self.remote_status.identity.1.clone(),
                    };
                    */

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
                    /*
                    let account = AccountDiff {
                        last_commit: Some(self.remote_status.account.0),
                        patch: reader
                            .diff(Some(&self.remote_status.account.0))
                            .await?,
                        checkpoint: self.remote_status.account.1.clone(),
                    };
                    */

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

        #[cfg(feature = "device")]
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
                    /*
                    let device = DeviceDiff {
                        last_commit: Some(self.remote_status.device.0),
                        patch: reader
                            .diff(Some(&self.remote_status.device.0))
                            .await?,
                        checkpoint: self.remote_status.device.1.clone(),
                    };
                    */

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
                            /*
                            let files = FileDiff {
                                last_commit: Some(remote_files.0),
                                patch: reader
                                    .diff(Some(&remote_files.0))
                                    .await?,
                                checkpoint: remote_files.1.clone(),
                            };
                            */

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

                    /*
                    let folder = FolderDiff {
                        last_commit: Some(commit_state.0),
                        patch: log.diff(Some(&commit_state.0)).await?,
                        checkpoint: commit_state.1.clone(),
                    };
                    */

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

/// Collection of patches for an account.
#[derive(Debug, Default)]
pub struct ChangeSet {
    /// Identity vault event logs.
    pub identity: FolderPatch,
    /// Account event logs.
    pub account: AccountPatch,
    /// Device event logs.
    #[cfg(feature = "device")]
    pub device: DevicePatch,
    /// File event logs.
    #[cfg(feature = "files")]
    pub files: FilePatch,
    /// Folders to be imported into the new account.
    pub folders: HashMap<VaultId, FolderPatch>,
}

/// Set of updates to the folders in an account.
///
/// Used to destructively update folders in an account;
/// the identity and folders are entire event
/// logs so that the account state can be overwritten in the
/// case of events such as changing encryption cipher, changing
/// folder password or compacing the events in a folder.
#[derive(Debug, Default, Clone)]
pub struct UpdateSet {
    /// Identity folder event logs.
    pub identity: Option<FolderDiff>,
    /// Account event log.
    pub account: Option<AccountDiff>,
    /// Device event log.
    #[cfg(feature = "device")]
    pub device: Option<DeviceDiff>,
    /// Files event log.
    #[cfg(feature = "files")]
    pub files: Option<FileDiff>,
    /// Folders to be updated.
    pub folders: HashMap<VaultId, FolderDiff>,
}

/// Storage implementations that can synchronize.
#[async_trait]
pub trait SyncStorage: StorageEventLogs {
    /// Get the sync status.
    async fn sync_status(&self) -> Result<SyncStatus>;

    /// Change set of all event logs.
    ///
    /// Used by network aware implementations to transfer
    /// entire accounts.
    async fn change_set(&self) -> Result<ChangeSet> {
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

        #[cfg(feature = "device")]
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
        let identifiers = self.folder_identifiers().await?;

        for id in &identifiers {
            let event_log = self.folder_log(id).await?;
            let log_file = event_log.read().await;
            folders.insert(*id, log_file.diff_events(None).await?);
        }

        Ok(ChangeSet {
            identity,
            account,
            folders,
            #[cfg(feature = "device")]
            device,
            #[cfg(feature = "files")]
            files,
        })
    }
}

fn is_zero(value: &usize) -> bool {
    value == &usize::MIN
}

/// Outcome of a merge operation.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MergeOutcome {
    /// Total number of changes made during the merge.
    #[serde(skip_serializing_if = "is_zero")]
    pub changes: usize,
    /// Number of changes to the identity folder.
    #[serde(skip_serializing_if = "is_zero")]
    pub identity: usize,
    /// Number of changes to the account event log.
    #[serde(skip_serializing_if = "is_zero")]
    pub account: usize,
    /// Number of changes to the device event log.
    #[cfg(feature = "device")]
    #[serde(skip_serializing_if = "is_zero")]
    pub device: usize,
    /// Number of changes to the file event log.
    #[cfg(feature = "files")]
    #[serde(skip_serializing_if = "is_zero")]
    pub file: usize,
    /// Number of changes to the folder event logs.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub folders: HashMap<VaultId, usize>,

    /// Collection of external files detected when merging
    /// file events logs.
    ///
    /// Used after mege to update the file transfer queue.
    #[cfg(feature = "files")]
    #[serde(skip)]
    pub external_files: IndexSet<ExternalFile>,
}

/// Types that can force merge a diff.
///
/// Force merge deletes all events from the log and
/// applies the diff patch as a new set of events.
///
/// Use this when event logs have completely diverged
/// and need to be rewritten.
#[async_trait]
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
    #[cfg(feature = "device")]
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
#[async_trait]
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
    ) -> Result<CheckedPatch>;

    /// Compare the account events.
    async fn compare_account(
        &self,
        state: &CommitState,
    ) -> Result<Comparison>;

    /// Merge changes to the devices event log.
    #[cfg(feature = "device")]
    async fn merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch>;

    /// Compare the device events.
    #[cfg(feature = "device")]
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
    ) -> Result<CheckedPatch>;

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

        #[cfg(feature = "device")]
        {
            compare.device =
                Some(self.compare_device(&remote_status.device).await?);
        }

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
            Some(MaybeDiff::Noop) => unreachable!(),
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

        match diff.account {
            Some(MaybeDiff::Noop) => unreachable!(),
            Some(MaybeDiff::Diff(diff)) => {
                self.merge_account(diff, outcome).await?;
            }
            Some(MaybeDiff::Compare(state)) => {
                if let Some(state) = state {
                    compare.account =
                        Some(self.compare_account(&state).await?);
                }
            }
            None => {}
        }

        #[cfg(feature = "device")]
        match diff.device {
            Some(MaybeDiff::Noop) => unreachable!(),
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
            Some(MaybeDiff::Noop) => unreachable!(),
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
            match maybe_diff {
                MaybeDiff::Noop => unreachable!(),
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
    let diff = comparison.diff(storage).await?;
    Ok((needs_sync, comparison.local_status, diff))
}
