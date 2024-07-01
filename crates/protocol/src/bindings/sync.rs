include!(concat!(env!("OUT_DIR"), "/sync.rs"));

use crate::{
    decode_uuid, encode_uuid,
    sdk::{
        commit::Comparison,
        events::{Diff, EventRecord, Patch},
    },
    CreateSet, Error, MaybeDiff, MergeOutcome, Origin, ProtoBinding, Result,
    SyncCompare, SyncDiff, SyncPacket, SyncStatus, TrackedAccountChange,
    TrackedChanges, TrackedDeviceChange, TrackedFolderChange, UpdateSet,
};
use indexmap::{IndexMap, IndexSet};
use std::collections::{HashMap, HashSet};

impl ProtoBinding for Origin {
    type Inner = WireOrigin;
}

impl TryFrom<WireOrigin> for Origin {
    type Error = Error;

    fn try_from(value: WireOrigin) -> Result<Self> {
        Ok(Self::new(value.name, value.url.parse()?))
    }
}

impl From<Origin> for WireOrigin {
    fn from(value: Origin) -> Self {
        Self {
            name: value.name().to_string(),
            url: value.url().to_string(),
        }
    }
}

impl ProtoBinding for SyncStatus {
    type Inner = WireSyncStatus;
}

impl TryFrom<WireSyncStatus> for SyncStatus {
    type Error = Error;

    fn try_from(value: WireSyncStatus) -> Result<Self> {
        #[cfg(feature = "files")]
        let files = if let Some(files) = value.files {
            Some(files.try_into()?)
        } else {
            None
        };

        let mut folders = IndexMap::with_capacity(value.folders.len());
        for folder in value.folders {
            folders.insert(
                decode_uuid(&folder.folder_id)?,
                folder.state.unwrap().try_into()?,
            );
        }

        Ok(Self {
            root: value.root.unwrap().try_into()?,
            identity: value.identity.unwrap().try_into()?,
            account: value.account.unwrap().try_into()?,
            device: value.device.unwrap().try_into()?,
            #[cfg(feature = "files")]
            files,
            folders,
        })
    }
}

impl From<SyncStatus> for WireSyncStatus {
    fn from(value: SyncStatus) -> Self {
        Self {
            root: Some(value.root.into()),
            identity: Some(value.identity.into()),
            account: Some(value.account.into()),
            device: Some(value.device.into()),
            #[cfg(feature = "files")]
            files: value.files.map(|s| s.into()),
            #[cfg(not(feature = "files"))]
            files: None,
            folders: value
                .folders
                .into_iter()
                .map(|(k, v)| WireSyncFolderState {
                    folder_id: encode_uuid(&k),
                    state: Some(v.into()),
                })
                .collect(),
        }
    }
}

impl ProtoBinding for Comparison {
    type Inner = WireComparison;
}

impl TryFrom<WireComparison> for Comparison {
    type Error = Error;

    fn try_from(value: WireComparison) -> Result<Self> {
        let inner = value.inner.unwrap();
        Ok(match inner {
            wire_comparison::Inner::Equal(_) => Self::Equal,
            wire_comparison::Inner::Contains(value) => Self::Contains(
                value.indices.into_iter().map(|i| i as usize).collect(),
            ),
            wire_comparison::Inner::Unknown(_) => Self::Unknown,
        })
    }
}

impl From<Comparison> for WireComparison {
    fn from(value: Comparison) -> Self {
        match value {
            Comparison::Equal => WireComparison {
                inner: Some(wire_comparison::Inner::Equal(true)),
            },
            Comparison::Contains(indices) => WireComparison {
                inner: Some(wire_comparison::Inner::Contains(Contains {
                    indices: indices.into_iter().map(|i| i as u64).collect(),
                })),
            },
            Comparison::Unknown => WireComparison {
                inner: Some(wire_comparison::Inner::Unknown(true)),
            },
        }
    }
}

impl<T> ProtoBinding for Patch<T> {
    type Inner = WirePatch;
}

impl<T> TryFrom<WirePatch> for Patch<T> {
    type Error = Error;

    fn try_from(value: WirePatch) -> Result<Self> {
        let mut records = Vec::with_capacity(value.records.len());
        for record in value.records {
            records.push(record.try_into()?);
        }
        Ok(Self::new(records))
    }
}

impl<T> From<Patch<T>> for WirePatch {
    fn from(value: Patch<T>) -> Self {
        let records: Vec<EventRecord> = value.into();
        Self {
            records: records.into_iter().map(|r| r.into()).collect(),
        }
    }
}

impl<T> ProtoBinding for Diff<T> {
    type Inner = WireDiff;
}

impl<T> TryFrom<WireDiff> for Diff<T> {
    type Error = Error;

    fn try_from(value: WireDiff) -> Result<Self> {
        let last_commit = if let Some(last_commit) = value.last_commit {
            Some(last_commit.try_into()?)
        } else {
            None
        };
        Ok(Self {
            last_commit,
            patch: value.patch.unwrap().try_into()?,
            checkpoint: value.checkpoint.unwrap().try_into()?,
        })
    }
}

impl<T> From<Diff<T>> for WireDiff {
    fn from(value: Diff<T>) -> Self {
        Self {
            last_commit: value.last_commit.map(|c| c.into()),
            patch: Some(value.patch.into()),
            checkpoint: Some(value.checkpoint.into()),
        }
    }
}

impl<T> ProtoBinding for MaybeDiff<T> {
    type Inner = WireMaybeDiff;
}

impl<T> TryFrom<WireMaybeDiff> for MaybeDiff<T>
where
    T: TryFrom<WireDiff, Error = Error>,
{
    type Error = Error;

    fn try_from(value: WireMaybeDiff) -> Result<Self> {
        let inner = value.inner.unwrap();

        match inner {
            wire_maybe_diff::Inner::Diff(value) => {
                Ok(Self::Diff(value.diff.unwrap().try_into()?))
            }
            wire_maybe_diff::Inner::Compare(value) => {
                let compare = if let Some(compare) = value.compare {
                    Some(compare.try_into()?)
                } else {
                    None
                };
                Ok(Self::Compare(compare))
            }
        }
    }
}

impl<T> From<MaybeDiff<T>> for WireMaybeDiff
where
    T: Into<WireDiff>,
{
    fn from(value: MaybeDiff<T>) -> Self {
        match value {
            MaybeDiff::<T>::Diff(diff) => WireMaybeDiff {
                inner: Some(wire_maybe_diff::Inner::Diff(
                    WireMaybeDiffHasDiff {
                        diff: Some(diff.into()),
                    },
                )),
            },
            MaybeDiff::<T>::Compare(compare) => WireMaybeDiff {
                inner: Some(wire_maybe_diff::Inner::Compare(
                    WireMaybeDiffNeedsCompare {
                        compare: compare.map(|c| c.into()),
                    },
                )),
            },
        }
    }
}

impl ProtoBinding for CreateSet {
    type Inner = WireCreateSet;
}

impl TryFrom<WireCreateSet> for CreateSet {
    type Error = Error;

    fn try_from(value: WireCreateSet) -> Result<Self> {
        let mut folders = HashMap::with_capacity(value.folders.len());
        for folder in value.folders {
            folders.insert(
                decode_uuid(&folder.folder_id)?,
                folder.patch.unwrap().try_into()?,
            );
        }
        Ok(Self {
            identity: value.identity.unwrap().try_into()?,
            account: value.account.unwrap().try_into()?,
            device: value.device.unwrap().try_into()?,
            #[cfg(feature = "files")]
            files: value.files.unwrap().try_into()?,
            folders,
        })
    }
}

impl From<CreateSet> for WireCreateSet {
    fn from(value: CreateSet) -> Self {
        Self {
            identity: Some(value.identity.into()),
            account: Some(value.account.into()),
            device: Some(value.device.into()),
            #[cfg(feature = "files")]
            files: Some(value.files.into()),
            #[cfg(not(feature = "files"))]
            files: None,
            folders: value
                .folders
                .into_iter()
                .map(|(k, v)| WireSyncFolderPatch {
                    folder_id: encode_uuid(&k),
                    patch: Some(v.into()),
                })
                .collect(),
        }
    }
}

impl ProtoBinding for UpdateSet {
    type Inner = WireUpdateSet;
}

impl TryFrom<WireUpdateSet> for UpdateSet {
    type Error = Error;

    fn try_from(value: WireUpdateSet) -> Result<Self> {
        let identity = if let Some(identity) = value.identity {
            Some(identity.try_into()?)
        } else {
            None
        };

        let account = if let Some(account) = value.account {
            Some(account.try_into()?)
        } else {
            None
        };

        let device = if let Some(device) = value.device {
            Some(device.try_into()?)
        } else {
            None
        };

        #[cfg(feature = "files")]
        let files = if let Some(files) = value.files {
            Some(files.try_into()?)
        } else {
            None
        };

        let mut folders = HashMap::with_capacity(value.folders.len());
        for folder in value.folders {
            folders.insert(
                decode_uuid(&folder.folder_id)?,
                folder.diff.unwrap().try_into()?,
            );
        }
        Ok(Self {
            identity,
            account,
            device,
            #[cfg(feature = "files")]
            files,
            folders,
        })
    }
}

impl From<UpdateSet> for WireUpdateSet {
    fn from(value: UpdateSet) -> Self {
        Self {
            identity: value.identity.map(|d| d.into()),
            account: value.account.map(|d| d.into()),
            device: value.device.map(|d| d.into()),
            #[cfg(feature = "files")]
            files: value.files.map(|d| d.into()),
            #[cfg(not(feature = "files"))]
            files: None,
            folders: value
                .folders
                .into_iter()
                .map(|(k, v)| WireSyncFolderDiff {
                    folder_id: encode_uuid(&k),
                    diff: Some(v.into()),
                })
                .collect(),
        }
    }
}

impl ProtoBinding for SyncDiff {
    type Inner = WireSyncDiff;
}

impl TryFrom<WireSyncDiff> for SyncDiff {
    type Error = Error;

    fn try_from(value: WireSyncDiff) -> Result<Self> {
        let identity = if let Some(identity) = value.identity {
            Some(identity.try_into()?)
        } else {
            None
        };

        let account = if let Some(account) = value.account {
            Some(account.try_into()?)
        } else {
            None
        };

        let device = if let Some(device) = value.device {
            Some(device.try_into()?)
        } else {
            None
        };

        #[cfg(feature = "files")]
        let files = if let Some(files) = value.files {
            Some(files.try_into()?)
        } else {
            None
        };

        let mut folders = IndexMap::with_capacity(value.folders.len());
        for folder in value.folders {
            folders.insert(
                decode_uuid(&folder.folder_id)?,
                folder.maybe_diff.unwrap().try_into()?,
            );
        }
        Ok(Self {
            identity,
            account,
            device,
            #[cfg(feature = "files")]
            files,
            folders,
        })
    }
}

impl From<SyncDiff> for WireSyncDiff {
    fn from(value: SyncDiff) -> Self {
        Self {
            identity: value.identity.map(|d| d.into()),
            account: value.account.map(|d| d.into()),
            device: value.device.map(|d| d.into()),
            #[cfg(feature = "files")]
            files: value.files.map(|d| d.into()),
            #[cfg(not(feature = "files"))]
            files: None,
            folders: value
                .folders
                .into_iter()
                .map(|(k, v)| WireSyncFolderMaybeDiff {
                    folder_id: encode_uuid(&k),
                    maybe_diff: Some(v.into()),
                })
                .collect(),
        }
    }
}

impl ProtoBinding for SyncCompare {
    type Inner = WireSyncCompare;
}

impl TryFrom<WireSyncCompare> for SyncCompare {
    type Error = Error;

    fn try_from(value: WireSyncCompare) -> Result<Self> {
        let identity = if let Some(identity) = value.identity {
            Some(identity.try_into()?)
        } else {
            None
        };

        let account = if let Some(account) = value.account {
            Some(account.try_into()?)
        } else {
            None
        };

        let device = if let Some(device) = value.device {
            Some(device.try_into()?)
        } else {
            None
        };

        #[cfg(feature = "files")]
        let files = if let Some(files) = value.files {
            Some(files.try_into()?)
        } else {
            None
        };

        let mut folders = IndexMap::with_capacity(value.folders.len());
        for folder in value.folders {
            folders.insert(
                decode_uuid(&folder.folder_id)?,
                folder.compare.unwrap().try_into()?,
            );
        }
        Ok(Self {
            identity,
            account,
            device,
            #[cfg(feature = "files")]
            files,
            folders,
        })
    }
}

impl From<SyncCompare> for WireSyncCompare {
    fn from(value: SyncCompare) -> Self {
        Self {
            identity: value.identity.map(|d| d.into()),
            account: value.account.map(|d| d.into()),
            device: value.device.map(|d| d.into()),
            #[cfg(feature = "files")]
            files: value.files.map(|d| d.into()),
            #[cfg(not(feature = "files"))]
            files: None,
            folders: value
                .folders
                .into_iter()
                .map(|(k, v)| WireSyncFolderComparison {
                    folder_id: encode_uuid(&k),
                    compare: Some(v.into()),
                })
                .collect(),
        }
    }
}

impl ProtoBinding for SyncPacket {
    type Inner = WireSyncPacket;
}

impl TryFrom<WireSyncPacket> for SyncPacket {
    type Error = Error;

    fn try_from(value: WireSyncPacket) -> Result<Self> {
        let compare = if let Some(compare) = value.compare {
            Some(compare.try_into()?)
        } else {
            None
        };

        Ok(Self {
            status: value.status.unwrap().try_into()?,
            diff: value.diff.unwrap().try_into()?,
            compare,
        })
    }
}

impl From<SyncPacket> for WireSyncPacket {
    fn from(value: SyncPacket) -> Self {
        Self {
            status: Some(value.status.into()),
            diff: Some(value.diff.into()),
            compare: value.compare.map(|c| c.into()),
        }
    }
}

impl ProtoBinding for MergeOutcome {
    type Inner = WireMergeOutcome;
}

impl TryFrom<WireMergeOutcome> for MergeOutcome {
    type Error = Error;

    fn try_from(value: WireMergeOutcome) -> Result<Self> {
        Ok(Self {
            changes: value.changes,
            tracked: value.tracked.unwrap().try_into()?,
            #[cfg(feature = "files")]
            external_files: IndexSet::new(),
        })
    }
}

impl From<MergeOutcome> for WireMergeOutcome {
    fn from(value: MergeOutcome) -> Self {
        Self {
            changes: value.changes,
            tracked: Some(value.tracked.into()),
        }
    }
}

impl ProtoBinding for TrackedChanges {
    type Inner = WireTrackedChanges;
}

impl TryFrom<WireTrackedChanges> for TrackedChanges {
    type Error = Error;

    fn try_from(value: WireTrackedChanges) -> Result<Self> {
        let mut identity = HashSet::with_capacity(value.identity.len());
        for change in value.identity {
            identity.insert(change.try_into()?);
        }

        let mut account = HashSet::with_capacity(value.account.len());
        for change in value.account {
            account.insert(change.try_into()?);
        }

        let mut device = HashSet::with_capacity(value.device.len());
        for change in value.device {
            device.insert(change.try_into()?);
        }

        #[cfg(feature = "files")]
        let files = {
            let mut files = HashSet::with_capacity(value.files.len());
            for change in value.files {
                files.insert(change.try_into()?);
            }
            files
        };

        let mut folders = HashMap::with_capacity(value.folders.len());
        for folder in value.folders {
            let mut changes = HashSet::with_capacity(folder.changes.len());
            for change in folder.changes {
                changes.insert(change.try_into()?);
            }
            folders.insert(decode_uuid(&folder.folder_id)?, changes);
        }

        Ok(Self {
            identity,
            account,
            device,
            #[cfg(feature = "files")]
            files,
            folders,
        })
    }
}

impl From<TrackedChanges> for WireTrackedChanges {
    fn from(value: TrackedChanges) -> Self {
        Self {
            identity: value.identity.into_iter().map(|c| c.into()).collect(),
            account: value.account.into_iter().map(|c| c.into()).collect(),
            device: value.device.into_iter().map(|c| c.into()).collect(),
            #[cfg(feature = "files")]
            files: value.files.into_iter().map(|c| c.into()).collect(),
            #[cfg(not(feature = "files"))]
            files: Default::default(),
            folders: value
                .folders
                .into_iter()
                .map(|(k, v)| WireTrackedUserFolderChange {
                    folder_id: encode_uuid(&k),
                    changes: v.into_iter().map(|c| c.into()).collect(),
                })
                .collect(),
        }
    }
}

impl ProtoBinding for TrackedAccountChange {
    type Inner = WireTrackedAccountChange;
}

impl TryFrom<WireTrackedAccountChange> for TrackedAccountChange {
    type Error = Error;

    fn try_from(value: WireTrackedAccountChange) -> Result<Self> {
        Ok(match value.inner.unwrap() {
            wire_tracked_account_change::Inner::FolderCreated(inner) => {
                TrackedAccountChange::FolderCreated(decode_uuid(
                    &inner.folder_id,
                )?)
            }
            wire_tracked_account_change::Inner::FolderUpdated(inner) => {
                TrackedAccountChange::FolderUpdated(decode_uuid(
                    &inner.folder_id,
                )?)
            }
            wire_tracked_account_change::Inner::FolderDeleted(inner) => {
                TrackedAccountChange::FolderDeleted(decode_uuid(
                    &inner.folder_id,
                )?)
            }
        })
    }
}

impl From<TrackedAccountChange> for WireTrackedAccountChange {
    fn from(value: TrackedAccountChange) -> Self {
        match value {
            TrackedAccountChange::FolderCreated(folder_id) => {
                WireTrackedAccountChange {
                    inner: Some(
                        wire_tracked_account_change::Inner::FolderCreated(
                            WireTrackedAccountFolderCreated {
                                folder_id: encode_uuid(&folder_id),
                            },
                        ),
                    ),
                }
            }
            TrackedAccountChange::FolderUpdated(folder_id) => {
                WireTrackedAccountChange {
                    inner: Some(
                        wire_tracked_account_change::Inner::FolderUpdated(
                            WireTrackedAccountFolderUpdated {
                                folder_id: encode_uuid(&folder_id),
                            },
                        ),
                    ),
                }
            }
            TrackedAccountChange::FolderDeleted(folder_id) => {
                WireTrackedAccountChange {
                    inner: Some(
                        wire_tracked_account_change::Inner::FolderDeleted(
                            WireTrackedAccountFolderDeleted {
                                folder_id: encode_uuid(&folder_id),
                            },
                        ),
                    ),
                }
            }
        }
    }
}

impl ProtoBinding for TrackedDeviceChange {
    type Inner = WireTrackedDeviceChange;
}

impl TryFrom<WireTrackedDeviceChange> for TrackedDeviceChange {
    type Error = Error;

    fn try_from(value: WireTrackedDeviceChange) -> Result<Self> {
        Ok(match value.inner.unwrap() {
            wire_tracked_device_change::Inner::Trusted(inner) => {
                TrackedDeviceChange::Trusted(
                    inner.device_public_key.as_slice().try_into()?,
                )
            }
            wire_tracked_device_change::Inner::Revoked(inner) => {
                TrackedDeviceChange::Revoked(
                    inner.device_public_key.as_slice().try_into()?,
                )
            }
        })
    }
}

impl From<TrackedDeviceChange> for WireTrackedDeviceChange {
    fn from(value: TrackedDeviceChange) -> Self {
        match value {
            TrackedDeviceChange::Trusted(device_public_key) => {
                WireTrackedDeviceChange {
                    inner: Some(wire_tracked_device_change::Inner::Trusted(
                        WireTrackedDeviceChangeTrusted {
                            device_public_key: device_public_key
                                .as_ref()
                                .to_vec(),
                        },
                    )),
                }
            }
            TrackedDeviceChange::Revoked(device_public_key) => {
                WireTrackedDeviceChange {
                    inner: Some(wire_tracked_device_change::Inner::Revoked(
                        WireTrackedDeviceChangeRevoked {
                            device_public_key: device_public_key
                                .as_ref()
                                .to_vec(),
                        },
                    )),
                }
            }
        }
    }
}

#[cfg(feature = "files")]
mod files {
    use sos_sdk::storage::files::SecretPath;

    use super::{
        wire_tracked_file_change, WireSecretPath, WireTrackedFileChange,
        WireTrackedFileDeleted, WireTrackedFileMoved,
    };
    use crate::{
        bindings::sync::WireTrackedFileCreated, decode_uuid, encode_uuid,
        Error, ProtoBinding, Result, TrackedFileChange,
    };

    impl ProtoBinding for TrackedFileChange {
        type Inner = WireTrackedFileChange;
    }

    impl TryFrom<WireTrackedFileChange> for TrackedFileChange {
        type Error = Error;

        fn try_from(value: WireTrackedFileChange) -> Result<Self> {
            Ok(match value.inner.unwrap() {
                wire_tracked_file_change::Inner::Created(inner) => {
                    TrackedFileChange::Created(
                        inner.owner.unwrap().try_into()?,
                        inner.file_name.as_slice().try_into()?,
                    )
                }
                wire_tracked_file_change::Inner::Moved(inner) => {
                    TrackedFileChange::Moved {
                        name: inner.name.as_slice().try_into()?,
                        from: inner.from.unwrap().try_into()?,
                        dest: inner.dest.unwrap().try_into()?,
                    }
                }
                wire_tracked_file_change::Inner::Deleted(inner) => {
                    TrackedFileChange::Deleted(
                        inner.owner.unwrap().try_into()?,
                        inner.file_name.as_slice().try_into()?,
                    )
                }
            })
        }
    }

    impl From<TrackedFileChange> for WireTrackedFileChange {
        fn from(value: TrackedFileChange) -> Self {
            match value {
                TrackedFileChange::Created(owner, file_name) => {
                    WireTrackedFileChange {
                        inner: Some(
                            wire_tracked_file_change::Inner::Created(
                                WireTrackedFileCreated {
                                    owner: Some(owner.into()),
                                    file_name: file_name.as_ref().to_vec(),
                                },
                            ),
                        ),
                    }
                }
                TrackedFileChange::Moved { name, from, dest } => {
                    WireTrackedFileChange {
                        inner: Some(wire_tracked_file_change::Inner::Moved(
                            WireTrackedFileMoved {
                                name: name.as_ref().to_vec(),
                                from: Some(from.into()),
                                dest: Some(dest.into()),
                            },
                        )),
                    }
                }
                TrackedFileChange::Deleted(owner, file_name) => {
                    WireTrackedFileChange {
                        inner: Some(
                            wire_tracked_file_change::Inner::Deleted(
                                WireTrackedFileDeleted {
                                    owner: Some(owner.into()),
                                    file_name: file_name.as_ref().to_vec(),
                                },
                            ),
                        ),
                    }
                }
            }
        }
    }

    impl TryFrom<WireSecretPath> for SecretPath {
        type Error = Error;

        fn try_from(value: WireSecretPath) -> Result<Self> {
            Ok(SecretPath(
                decode_uuid(&value.folder_id)?,
                decode_uuid(&value.secret_id)?,
            ))
        }
    }

    impl From<SecretPath> for WireSecretPath {
        fn from(value: SecretPath) -> Self {
            WireSecretPath {
                folder_id: encode_uuid(&value.0),
                secret_id: encode_uuid(&value.1),
            }
        }
    }
}

impl ProtoBinding for TrackedFolderChange {
    type Inner = WireTrackedFolderChange;
}

impl TryFrom<WireTrackedFolderChange> for TrackedFolderChange {
    type Error = Error;

    fn try_from(value: WireTrackedFolderChange) -> Result<Self> {
        Ok(match value.inner.unwrap() {
            wire_tracked_folder_change::Inner::Created(inner) => {
                TrackedFolderChange::Created(decode_uuid(&inner.secret_id)?)
            }
            wire_tracked_folder_change::Inner::Updated(inner) => {
                TrackedFolderChange::Updated(decode_uuid(&inner.secret_id)?)
            }
            wire_tracked_folder_change::Inner::Deleted(inner) => {
                TrackedFolderChange::Deleted(decode_uuid(&inner.secret_id)?)
            }
        })
    }
}

impl From<TrackedFolderChange> for WireTrackedFolderChange {
    fn from(value: TrackedFolderChange) -> Self {
        match value {
            TrackedFolderChange::Created(secret_id) => {
                WireTrackedFolderChange {
                    inner: Some(wire_tracked_folder_change::Inner::Created(
                        WireTrackedFolderChangeCreated {
                            secret_id: encode_uuid(&secret_id),
                        },
                    )),
                }
            }
            TrackedFolderChange::Updated(secret_id) => {
                WireTrackedFolderChange {
                    inner: Some(wire_tracked_folder_change::Inner::Updated(
                        WireTrackedFolderChangeUpdated {
                            secret_id: encode_uuid(&secret_id),
                        },
                    )),
                }
            }
            TrackedFolderChange::Deleted(secret_id) => {
                WireTrackedFolderChange {
                    inner: Some(wire_tracked_folder_change::Inner::Deleted(
                        WireTrackedFolderChangeDeleted {
                            secret_id: encode_uuid(&secret_id),
                        },
                    )),
                }
            }
        }
    }
}
