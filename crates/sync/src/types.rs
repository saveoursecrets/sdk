//! Core types for the synchronization primitives.
use crate::Result;
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use sos_core::{
    AccountId, SecretId, VaultId,
    commit::{CommitHash, CommitState, Comparison},
};
use sos_core::{
    device::DevicePublicKey,
    events::{
        AccountEvent, DeviceEvent, WriteEvent,
        patch::{
            AccountDiff, AccountPatch, DeviceDiff, DevicePatch, FolderDiff,
            FolderPatch,
        },
    },
};
use sos_vault::Summary;
use std::collections::HashMap;

#[cfg(feature = "files")]
use sos_core::{
    ExternalFile, ExternalFileName, SecretPath,
    events::{
        FileEvent,
        patch::{FileDiff, FilePatch},
    },
};

/// Debug snapshot of an account events at a point in time.
///
/// Can be used as a debugging tool to aid in determining
/// where account events on different machines have diverged.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugTree {
    /// Account identifier.
    pub account_id: AccountId,
    /// User folders.
    pub folders: IndexSet<Summary>,
    /// Sync status.
    pub status: SyncStatus,
    /// Event logs.
    pub events: DebugEventLogs,
}

/// Collection of event logs for an account tree.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DebugEventLogs {
    /// Identity folder events.
    pub identity: DebugEvents,
    /// Account level events.
    pub account: DebugEvents,
    /// Device level events.
    pub device: DebugEvents,
    /// File level events.
    #[cfg(feature = "files")]
    pub file: DebugEvents,
    /// Folder level events.
    pub folders: HashMap<VaultId, DebugEvents>,
}

/// Collection of event logs for an account tree.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DebugEvents {
    /// Leaves in the merkle tree.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub leaves: Vec<CommitHash>,
    /// Number of leaves in the tree.
    pub length: usize,
    /// Computed root of the merkle tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<CommitHash>,
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

/// Provides a status overview of an account.
///
/// Intended to be used during a synchronization protocol.
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
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
    ///
    /// Will often be different to the number of tracked changes
    /// as tracked changes are normalized.
    pub changes: u64,

    /// Tracked changes made during a merge.
    ///
    /// These events can be used by client implementations
    /// to react to changes on other devices but they are not
    /// an exact representation of what was merged as tracked
    /// changes are normalized.
    ///
    /// For example, a create secret followed by a deletion of
    /// the same secret will result in both events being omitted.
    ///
    /// Tracked changes are normalized for all event types.
    ///
    /// Not all events are tracked, for example, renaming a folder
    /// triggers events on the account event log and also on the
    /// folder but only the account level events are tracked.
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
    pub identity: IndexSet<TrackedFolderChange>,

    /// Changes made to the devices collection.
    pub device: IndexSet<TrackedDeviceChange>,

    /// Changes made to the account.
    pub account: IndexSet<TrackedAccountChange>,

    /// Changes to the files log.
    #[cfg(feature = "files")]
    pub files: IndexSet<TrackedFileChange>,

    /// Change made to each folder.
    pub folders: HashMap<VaultId, IndexSet<TrackedFolderChange>>,
}

impl TrackedChanges {
    /// Add tracked folder changes only when
    /// the set of tracked changes is not empty.
    pub fn add_tracked_folder_changes(
        &mut self,
        folder_id: &VaultId,
        changes: IndexSet<TrackedFolderChange>,
    ) {
        if !changes.is_empty() {
            self.folders.insert(*folder_id, changes);
        }
    }

    /// Create a new set of tracked changes to a folder from a patch.
    pub async fn new_folder_records(
        value: &FolderPatch,
    ) -> Result<IndexSet<TrackedFolderChange>> {
        let events = value.into_events::<WriteEvent>().await?;
        Self::new_folder_events(events).await
    }

    /// Create a new set of tracked changes from a
    /// collection of folder events.
    pub async fn new_folder_events(
        events: Vec<WriteEvent>,
    ) -> Result<IndexSet<TrackedFolderChange>> {
        let mut changes = IndexSet::new();
        for event in events {
            match event {
                WriteEvent::CreateSecret(secret_id, _) => {
                    changes.insert(TrackedFolderChange::Created(secret_id));
                }
                WriteEvent::UpdateSecret(secret_id, _) => {
                    changes.insert(TrackedFolderChange::Updated(secret_id));
                }
                WriteEvent::DeleteSecret(secret_id) => {
                    let created = TrackedFolderChange::Created(secret_id);
                    let updated = TrackedFolderChange::Updated(secret_id);
                    let had_created = changes.shift_remove(&created);
                    changes.shift_remove(&updated);
                    if !had_created {
                        changes
                            .insert(TrackedFolderChange::Deleted(secret_id));
                    }
                }
                _ => {}
            }
        }
        Ok(changes)
    }

    /// Create a new set of tracked changes to an account from a patch.
    pub async fn new_account_records(
        value: &AccountPatch,
    ) -> Result<IndexSet<TrackedAccountChange>> {
        let events = value.into_events::<AccountEvent>().await?;
        Self::new_account_events(events).await
    }

    /// Create a new set of tracked changes from a
    /// collection of account events.
    pub async fn new_account_events(
        events: Vec<AccountEvent>,
    ) -> Result<IndexSet<TrackedAccountChange>> {
        let mut changes = IndexSet::new();
        for event in events {
            match event {
                AccountEvent::CreateFolder(folder_id, _) => {
                    changes.insert(TrackedAccountChange::FolderCreated(
                        folder_id,
                    ));
                }
                AccountEvent::RenameFolder(folder_id, _)
                | AccountEvent::UpdateFolder(folder_id, _) => {
                    changes.insert(TrackedAccountChange::FolderUpdated(
                        folder_id,
                    ));
                }
                AccountEvent::DeleteFolder(folder_id) => {
                    let created =
                        TrackedAccountChange::FolderCreated(folder_id);
                    let updated =
                        TrackedAccountChange::FolderUpdated(folder_id);
                    let had_created = changes.shift_remove(&created);
                    changes.shift_remove(&updated);

                    if !had_created {
                        changes.insert(TrackedAccountChange::FolderDeleted(
                            folder_id,
                        ));
                    }
                }
                _ => {}
            }
        }
        Ok(changes)
    }

    /// Create a new set of tracked changes to a device from a patch.
    pub async fn new_device_records(
        value: &DevicePatch,
    ) -> Result<IndexSet<TrackedDeviceChange>> {
        let events = value.into_events::<DeviceEvent>().await?;
        Self::new_device_events(events).await
    }

    /// Create a new set of tracked changes from a
    /// collection of device events.
    pub async fn new_device_events(
        events: Vec<DeviceEvent>,
    ) -> Result<IndexSet<TrackedDeviceChange>> {
        let mut changes = IndexSet::new();
        for event in events {
            match event {
                DeviceEvent::Trust(device) => {
                    changes.insert(TrackedDeviceChange::Trusted(
                        device.public_key().to_owned(),
                    ));
                }
                DeviceEvent::Revoke(public_key) => {
                    let trusted = TrackedDeviceChange::Trusted(public_key);
                    let had_trusted = changes.shift_remove(&trusted);
                    if !had_trusted {
                        changes
                            .insert(TrackedDeviceChange::Revoked(public_key));
                    }
                }
                _ => {}
            }
        }
        Ok(changes)
    }

    /// Create a new set of tracked changes to a file from a patch.
    #[cfg(feature = "files")]
    pub async fn new_file_records(
        value: &FilePatch,
    ) -> Result<IndexSet<TrackedFileChange>> {
        let events = value.into_events::<FileEvent>().await?;
        Self::new_file_events(events).await
    }

    /// Create a new set of tracked changes from a
    /// collection of file events.
    #[cfg(feature = "files")]
    pub async fn new_file_events(
        events: Vec<FileEvent>,
    ) -> Result<IndexSet<TrackedFileChange>> {
        let mut changes = IndexSet::new();
        for event in events {
            match event {
                FileEvent::CreateFile(owner, name) => {
                    changes.insert(TrackedFileChange::Created(owner, name));
                }
                FileEvent::MoveFile { name, from, dest } => {
                    changes.insert(TrackedFileChange::Moved {
                        name,
                        from,
                        dest,
                    });
                }
                FileEvent::DeleteFile(owner, name) => {
                    let created = TrackedFileChange::Created(owner, name);
                    let had_created = changes.shift_remove(&created);

                    let moved = changes.iter().find_map(|event| {
                        if let TrackedFileChange::Moved {
                            name: moved_name,
                            dest,
                            from,
                        } = event
                            && moved_name == &name
                            && dest == &owner
                        {
                            return Some(TrackedFileChange::Moved {
                                name: *moved_name,
                                from: *from,
                                dest: *dest,
                            });
                        }
                        None
                    });
                    if let Some(moved) = moved {
                        changes.shift_remove(&moved);
                    }

                    if !had_created {
                        changes
                            .insert(TrackedFileChange::Deleted(owner, name));
                    }
                }
                _ => {}
            }
        }
        Ok(changes)
    }
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
    Created(SecretPath, ExternalFileName),
    /// File was moved in the log.
    Moved {
        /// File name.
        name: ExternalFileName,
        /// From identifiers.
        from: SecretPath,
        /// Destination identifiers.
        dest: SecretPath,
    },
    /// File was deleted in the log.
    Deleted(SecretPath, ExternalFileName),
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
