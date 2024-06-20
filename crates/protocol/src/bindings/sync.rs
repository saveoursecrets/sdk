include!(concat!(env!("OUT_DIR"), "/sync.rs"));

use crate::{
    decode_uuid, encode_uuid,
    sdk::{
        commit::Comparison,
        events::{Diff, EventRecord, Patch},
    },
    CreateSet, Error, MaybeDiff, MergeOutcome, Origin, ProtoBinding, Result,
    SyncCompare, SyncDiff, SyncPacket, SyncStatus, UpdateSet,
};
use indexmap::{IndexMap, IndexSet};
use std::collections::HashMap;

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
            #[cfg(feature = "device")]
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
            #[cfg(feature = "device")]
            device: Some(value.device.into()),
            #[cfg(not(feature = "device"))]
            device: None,
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
            #[cfg(feature = "device")]
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
            #[cfg(feature = "device")]
            device: Some(value.device.into()),
            #[cfg(not(feature = "device"))]
            device: None,
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

        #[cfg(feature = "device")]
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
            #[cfg(feature = "device")]
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
            #[cfg(feature = "device")]
            device: value.device.map(|d| d.into()),
            #[cfg(not(feature = "device"))]
            device: None,
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

        #[cfg(feature = "device")]
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
            #[cfg(feature = "device")]
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
            #[cfg(feature = "device")]
            device: value.device.map(|d| d.into()),
            #[cfg(not(feature = "device"))]
            device: None,
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

        #[cfg(feature = "device")]
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
            #[cfg(feature = "device")]
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
            #[cfg(feature = "device")]
            device: value.device.map(|d| d.into()),
            #[cfg(not(feature = "device"))]
            device: None,
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
        let mut folders = HashMap::with_capacity(value.folders.len());
        for folder in value.folders {
            folders.insert(decode_uuid(&folder.folder_id)?, folder.changes);
        }

        Ok(Self {
            changes: value.changes,
            identity: value.identity,
            account: value.account,
            #[cfg(feature = "device")]
            device: value.device,
            #[cfg(feature = "files")]
            files: value.files,
            folders,
            #[cfg(feature = "files")]
            external_files: IndexSet::new(),
        })
    }
}

impl From<MergeOutcome> for WireMergeOutcome {
    fn from(value: MergeOutcome) -> Self {
        Self {
            changes: value.changes,
            identity: value.identity,
            account: value.account,
            #[cfg(feature = "device")]
            device: value.device,
            #[cfg(not(feature = "device"))]
            device: 0,
            #[cfg(feature = "files")]
            files: value.files,
            #[cfg(not(feature = "files"))]
            files: 0,
            folders: value
                .folders
                .into_iter()
                .map(|(k, v)| WireFolderMergeOutcome {
                    folder_id: encode_uuid(&k),
                    changes: v,
                })
                .collect(),
        }
    }
}
