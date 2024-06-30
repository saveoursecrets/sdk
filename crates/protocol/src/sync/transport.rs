//! Synchronization types that are sent
//! between the client and server.
use crate::sdk::{
    commit::{CommitHash, CommitState, Comparison},
    device::DevicePublicKey,
    events::{
        AccountDiff, AccountPatch, DeviceDiff, DevicePatch, FolderDiff,
        FolderPatch,
    },
    vault::{secret::SecretId, VaultId},
};
use crate::sync::MaybeConflict;
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    hash::{Hash, Hasher},
};
use url::Url;

#[cfg(feature = "files")]
use crate::sdk::{
    events::{FileDiff, FilePatch},
    storage::files::{ExternalFile, ExternalFileName, FileOwner},
};

/// Types of event logs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EventLogType {
    /// Identity folder event log.
    Identity,
    /// Account event log.
    Account,
    /// Device event log.
    Device,
    /// Files event log.
    #[cfg(feature = "files")]
    Files,
    /// Folder event log.
    Folder(VaultId),
}

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

/// Combined sync status, diff and comparisons.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
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

/// Diff of events or conflict information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaybeDiff<T> {
    /// Diff of local changes to send to the remote.
    Diff(T),
    /// Local needs to compare it's state with remote.
    // The additional `Option` wrapper is required because
    // the files event log may not exist.
    Compare(Option<CommitState>),
}

/// Diff between all events logs on local and remote.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct SyncDiff {
    /// Diff of the identity vault event logs.
    pub identity: Option<MaybeDiff<FolderDiff>>,
    /// Diff of the account event log.
    pub account: Option<MaybeDiff<AccountDiff>>,
    /// Diff of the device event log.
    pub device: Option<MaybeDiff<DeviceDiff>>,
    /// Diff of the files event log.
    #[cfg(feature = "files")]
    pub files: Option<MaybeDiff<FileDiff>>,
    /// Diff for folders in the account.
    pub folders: IndexMap<VaultId, MaybeDiff<FolderDiff>>,
}

/// Collection of patches for an account.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CreateSet {
    /// Identity vault event logs.
    pub identity: FolderPatch,
    /// Account event logs.
    pub account: AccountPatch,
    /// Device event logs.
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
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UpdateSet {
    /// Identity folder event logs.
    pub identity: Option<FolderDiff>,
    /// Account event log.
    pub account: Option<AccountDiff>,
    /// Device event log.
    pub device: Option<DeviceDiff>,
    /// Files event log.
    #[cfg(feature = "files")]
    pub files: Option<FileDiff>,
    /// Folders to be updated.
    pub folders: HashMap<VaultId, FolderDiff>,
}

/// Outcome of a merge operation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MergeOutcome {
    /// Total number of changes made during a merge.
    pub changes: u64,
    /// Tracked changes that were made during a merge.
    pub tracked: TrackedChanges,

    /// Collection of external files detected when merging
    /// file events logs, must never be serialized over
    /// the wire.
    ///
    /// Used after merge to update the file transfer queue.
    #[doc(hidden)]
    #[cfg(feature = "files")]
    pub external_files: IndexSet<ExternalFile>,
}

/// Changes tracking during a merge operation.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TrackedChanges {
    /// Changes made to the identity folder.
    pub identity: HashSet<TrackedFolderChange>,

    /// Changes made to the devices collection.
    pub device: HashSet<TrackedDeviceChange>,

    /// Changes made to the account.
    pub account: HashSet<TrackedAccountChange>,

    /// Changes to the files log.
    #[cfg(feature = "files")]
    pub files: HashSet<TrackedFileChange>,

    /// Change made to each folder.
    pub folders: HashMap<VaultId, HashSet<TrackedFolderChange>>,
}

/// Change made to a device.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum TrackedDeviceChange {
    /// Device was trusted.
    Trusted(DevicePublicKey),
    /// Device was revoked.
    Revoked(DevicePublicKey),
}

/// Change made to an account.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum TrackedAccountChange {
    /// Folder was added.
    FolderCreated(VaultId),
    /// Folder was updated.
    FolderUpdated(VaultId),
    /// Folder was deleted.
    FolderDeleted(VaultId),
}

/// Change made to file event logs.
#[cfg(feature = "files")]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum TrackedFileChange {
    /// File was created in the log.
    Created(FileOwner, ExternalFileName),
    /// File was moved in the log.
    Moved {
        /// File name.
        name: ExternalFileName,
        /// From identifiers.
        from: FileOwner,
        /// Destination identifiers.
        dest: FileOwner,
    },
    /// File was deleted in the log.
    Deleted(FileOwner, ExternalFileName),
}

/// Change made to a folder.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum TrackedFolderChange {
    /// Secret was created.
    Created(SecretId),
    /// Secret was updated.
    Updated(SecretId),
    /// Secret was deleted.
    Deleted(SecretId),
}
