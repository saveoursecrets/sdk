//! Synchronization primitives.

use crate::{
    commit::{CommitHash, CommitProof, CommitState, Comparison},
    events::{
        AccountEvent, AccountEventLog, EventLogExt, FolderEventLog,
        WriteEvent,
    },
    vault::VaultId,
    Error, Result,
};
use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    hash::{Hash, Hasher},
    path::Path,
    sync::Arc,
};
use tokio::sync::RwLock;
use url::Url;

mod patch;
pub use patch::{AccountPatch, FolderPatch, Patch};

#[cfg(feature = "device")]
use crate::events::{DeviceEvent, DeviceEventLog};

#[cfg(feature = "device")]
pub use patch::DevicePatch;

#[cfg(feature = "files")]
use crate::events::{FileEvent, FileEventLog};

#[cfg(feature = "files")]
pub use patch::FilePatch;

/// Server origin information.
#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct Origin {
    name: String,
    url: Url,
}

impl Origin {
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

/// Options for sync operation.
#[derive(Default, Debug)]
pub struct SyncOptions {
    /// Only sync these origins.
    pub origins: Vec<Origin>,
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
#[derive(Debug)]
pub enum CheckedPatch {
    /// Patch was applied.
    Success(CommitProof, Vec<CommitHash>),
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
#[derive(Default, Debug)]
pub struct Diff<T>
where
    T: Default + Encodable + Decodable,
{
    /// Last commit hash before the patch.
    pub last_commit: Option<CommitHash>,
    /// Contents of the patch.
    pub patch: Patch<T>,
    /// Head of the event log before applying the patch.
    pub before: CommitProof,
    /// Head of the event log after applying the patch.
    pub after: CommitProof,
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
#[derive(Debug, Default)]
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

/// Diff of events or conflict information.
#[derive(Default, Debug)]
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
#[derive(Default, Debug)]
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
            Comparison::Contains(_, _) => {
                // Need to push changes to remote
                let log = storage.identity_log().await?;
                let reader = log.read().await;
                let is_last_commit = Some(&self.remote_status.identity.0)
                    == reader.tree().last_commit().as_ref();

                // Avoid empty patches when commit is already the last
                if !is_last_commit {
                    let after = reader.tree().head()?;
                    let identity = FolderDiff {
                        last_commit: Some(self.remote_status.identity.0),
                        patch: reader
                            .diff(Some(&self.remote_status.identity.0))
                            .await?,
                        after,
                        before: self.remote_status.identity.1.clone(),
                    };
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
            Comparison::Contains(_, _) => {
                // Need to push changes to remote
                let log = storage.account_log().await?;
                let reader = log.read().await;

                let is_last_commit = Some(&self.remote_status.account.0)
                    == reader.tree().last_commit().as_ref();

                // Avoid empty patches when commit is already the last
                if !is_last_commit {
                    let after = reader.tree().head()?;
                    let account = AccountDiff {
                        last_commit: Some(self.remote_status.account.0),
                        patch: reader
                            .diff(Some(&self.remote_status.account.0))
                            .await?,
                        after,
                        before: self.remote_status.account.1.clone(),
                    };
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
            Comparison::Contains(_, _) => {
                // Need to push changes to remote
                let log = storage.device_log().await?;
                let reader = log.read().await;

                let is_last_commit = Some(&self.remote_status.device.0)
                    == reader.tree().last_commit().as_ref();

                // Avoid empty patches when commit is already the last
                if !is_last_commit {
                    let after = reader.tree().head()?;
                    let device = DeviceDiff {
                        last_commit: Some(self.remote_status.device.0),
                        patch: reader
                            .diff(Some(&self.remote_status.device.0))
                            .await?,
                        after,
                        before: self.remote_status.device.1.clone(),
                    };
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
                    Comparison::Contains(_, _) => {
                        // Need to push changes to remote
                        let log = storage.file_log().await?;
                        let reader = log.read().await;

                        let is_last_commit = Some(&remote_files.0)
                            == reader.tree().last_commit().as_ref();

                        // Avoid empty patches when commit is already the last
                        if !is_last_commit {
                            let after = reader.tree().head()?;
                            let files = FileDiff {
                                last_commit: Some(remote_files.0),
                                patch: reader
                                    .diff(Some(&remote_files.0))
                                    .await?,
                                after,
                                before: remote_files.1.clone(),
                            };
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
                    let after = reader.tree().head()?;
                    let files = FileDiff {
                        last_commit: None,
                        patch: reader.diff(None).await?,
                        after,
                        before: Default::default(),
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
                Comparison::Contains(_, _) => {
                    // Need to push changes to remote
                    let log = storage.folder_log(id).await?;
                    let log = log.read().await;

                    let after = log.tree().head()?;
                    let folder = FolderDiff {
                        last_commit: Some(commit_state.0),
                        patch: log.diff(Some(&commit_state.0)).await?,
                        after,
                        before: commit_state.1.clone(),
                    };

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
                let after = log.tree().commit_state()?.1;

                let folder = FolderDiff {
                    last_commit: Some(first_commit.0),
                    patch: log.diff(Some(&first_commit.0)).await?,
                    after,
                    before: first_commit.1,
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
#[derive(Default)]
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
/// the account, device and file event logs are applied
/// as diffs but the identity and folders are entire event
/// logs so that the account state can be overwritten in the
/// case of events such as changing encryption cipher, changing
/// folder password or compacing the events in a folder.
#[derive(Default)]
pub struct UpdateSet {
    /// Identity vault event logs.
    pub identity: Option<FolderPatch>,
    /// Folders to be imported into the new account.
    pub folders: HashMap<VaultId, FolderPatch>,
}

/// Client that can synchronize with a remote server.
#[async_trait]
pub trait SyncClient {
    /// Errors produced by the client.
    type Error: std::fmt::Debug;

    /// Origin of the remote server.
    fn origin(&self) -> &Origin;

    /// Create a new account.
    async fn create_account(
        &self,
        account: &ChangeSet,
    ) -> std::result::Result<(), Self::Error>;

    /// Update an account.
    async fn update_account(
        &self,
        account: &UpdateSet,
    ) -> std::result::Result<(), Self::Error>;

    /// Fetch an account from a remote server.
    async fn fetch_account(
        &self,
    ) -> std::result::Result<ChangeSet, Self::Error>;

    /// Sync status on remote, the result is `None` when the
    /// account does not exist.
    async fn sync_status(
        &self,
    ) -> std::result::Result<Option<SyncStatus>, Self::Error>;

    /// Sync with a remote.
    async fn sync(
        &self,
        packet: &SyncPacket,
    ) -> std::result::Result<SyncPacket, Self::Error>;

    /// Patch the device event log.
    #[cfg(feature = "device")]
    async fn patch_devices(
        &self,
        diff: &crate::sync::DeviceDiff,
    ) -> std::result::Result<(), Self::Error>;

    /// Send a file.
    #[cfg(feature = "files")]
    async fn upload_file(
        &self,
        file_info: &crate::storage::files::ExternalFile,
        path: &Path,
        progress: Arc<crate::storage::files::ProgressChannel>,
    ) -> std::result::Result<http::StatusCode, Self::Error>;

    /// Receive a file.
    #[cfg(feature = "files")]
    async fn download_file(
        &self,
        file_info: &crate::storage::files::ExternalFile,
        path: &Path,
        progress: Arc<crate::storage::files::ProgressChannel>,
    ) -> std::result::Result<http::StatusCode, Self::Error>;

    /// Delete a file on the remote server.
    #[cfg(feature = "files")]
    async fn delete_file(
        &self,
        file_info: &crate::storage::files::ExternalFile,
    ) -> std::result::Result<http::StatusCode, Self::Error>;

    /// Move a file on the remote server.
    #[cfg(feature = "files")]
    async fn move_file(
        &self,
        from: &crate::storage::files::ExternalFile,
        to: &crate::storage::files::ExternalFile,
    ) -> std::result::Result<http::StatusCode, Self::Error>;

    /// Compare local files with a remote server.
    ///
    /// Used to build a transfer queue that will eventually ensure
    /// external files are in sync.
    ///
    /// Comparing sets of files is expensive as both local and remote
    /// need to read the external files state from disc so only use this
    /// when necessary.
    #[cfg(feature = "files")]
    async fn compare_files(
        &self,
        local_files: &crate::storage::files::FileSet,
    ) -> std::result::Result<
        crate::storage::files::FileTransfersSet,
        Self::Error,
    >;
}

/// Storage implementations that can synchronize.
#[async_trait]
pub trait SyncStorage {
    /// Get the sync status.
    async fn sync_status(&self) -> Result<SyncStatus>;

    /// Clone of the identity log.
    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>>;

    /// Clone of the account log.
    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>>;

    /// Clone of the device log.
    #[cfg(feature = "device")]
    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>>;

    /// Clone of the file log.
    #[cfg(feature = "files")]
    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>>;

    /// Folder identifiers managed by this storage.
    async fn folder_identifiers(&self) -> Result<Vec<VaultId>>;

    /// Folder event log.
    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>>;

    /// Change set of all event logs.
    ///
    /// Used by network aware implementations to transfer
    /// entire accounts.
    async fn change_set(&self) -> Result<ChangeSet> {
        let identity = {
            let log = self.identity_log().await?;
            let reader = log.read().await;
            reader.diff(None).await?
        };

        let account = {
            let log = self.account_log().await?;
            let reader = log.read().await;
            reader.diff(None).await?
        };

        #[cfg(feature = "device")]
        let device = {
            let log = self.device_log().await?;
            let reader = log.read().await;
            reader.diff(None).await?
        };

        #[cfg(feature = "files")]
        let files = {
            let log = self.file_log().await?;
            let reader = log.read().await;
            reader.diff(None).await?
        };

        let mut folders = HashMap::new();
        let identifiers = self.folder_identifiers().await?;

        for id in &identifiers {
            let event_log = self.folder_log(id).await?;
            let log_file = event_log.read().await;
            folders.insert(*id, log_file.diff(None).await?);
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

/// Types that can merge diffs.
#[async_trait]
pub trait Merge {
    /// Merge changes to the identity folder.
    async fn merge_identity(&mut self, diff: &FolderDiff) -> Result<usize>;

    /// Compare the identity folder.
    async fn compare_identity(
        &self,
        state: &CommitState,
    ) -> Result<Comparison>;

    /// Merge changes to the account event log.
    async fn merge_account(&mut self, diff: &AccountDiff) -> Result<usize>;

    /// Compare the account events.
    async fn compare_account(
        &self,
        state: &CommitState,
    ) -> Result<Comparison>;

    /// Merge changes to the devices event log.
    #[cfg(feature = "device")]
    async fn merge_device(&mut self, diff: &DeviceDiff) -> Result<usize>;

    /// Compare the device events.
    #[cfg(feature = "device")]
    async fn compare_device(&self, state: &CommitState)
        -> Result<Comparison>;

    /// Merge changes to the files event log.
    #[cfg(feature = "files")]
    async fn merge_files(&mut self, diff: &FileDiff) -> Result<usize>;

    /// Compare the file events.
    #[cfg(feature = "files")]
    async fn compare_files(&self, state: &CommitState) -> Result<Comparison>;

    /// Merge changes to a folder.
    async fn merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: &FolderDiff,
    ) -> Result<usize>;

    /// Compare folder events.
    async fn compare_folder(
        &self,
        folder_id: &VaultId,
        state: &CommitState,
    ) -> Result<Comparison>;

    /// Merge a diff into this storage.
    async fn merge(
        &mut self,
        diff: &SyncDiff,
    ) -> Result<(usize, SyncCompare)> {
        //let span = span!(Level::DEBUG, "merge");
        //let _enter = span.enter();

        let mut num_changes = 0;
        let mut compare = SyncCompare::default();

        match &diff.identity {
            Some(MaybeDiff::Noop) => unreachable!(),
            Some(MaybeDiff::Diff(diff)) => {
                num_changes += self.merge_identity(diff).await?;
            }
            Some(MaybeDiff::Compare(state)) => {
                if let Some(state) = state {
                    compare.identity =
                        Some(self.compare_identity(state).await?);
                }
            }
            None => {}
        }

        match &diff.account {
            Some(MaybeDiff::Noop) => unreachable!(),
            Some(MaybeDiff::Diff(diff)) => {
                num_changes += self.merge_account(diff).await?;
            }
            Some(MaybeDiff::Compare(state)) => {
                if let Some(state) = state {
                    compare.account =
                        Some(self.compare_account(state).await?);
                }
            }
            None => {}
        }

        #[cfg(feature = "device")]
        match &diff.device {
            Some(MaybeDiff::Noop) => unreachable!(),
            Some(MaybeDiff::Diff(diff)) => {
                num_changes += self.merge_device(diff).await?;
            }
            Some(MaybeDiff::Compare(state)) => {
                if let Some(state) = state {
                    compare.device = Some(self.compare_device(state).await?);
                }
            }
            None => {}
        }

        #[cfg(feature = "files")]
        match &diff.files {
            Some(MaybeDiff::Noop) => unreachable!(),
            Some(MaybeDiff::Diff(diff)) => {
                num_changes += self.merge_files(diff).await?;
            }
            Some(MaybeDiff::Compare(state)) => {
                if let Some(state) = state {
                    compare.files = Some(self.compare_files(state).await?);
                }
            }
            None => {}
        }

        for (id, maybe_diff) in &diff.folders {
            match maybe_diff {
                MaybeDiff::Noop => unreachable!(),
                MaybeDiff::Diff(diff) => {
                    num_changes += self.merge_folder(id, diff).await?;
                }
                MaybeDiff::Compare(state) => {
                    if let Some(state) = state {
                        compare.folders.insert(
                            *id,
                            self.compare_folder(id, state).await?,
                        );
                    }
                }
            }
        }

        tracing::debug!(num_changes = %num_changes, "merge complete");

        Ok((num_changes, compare))
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
