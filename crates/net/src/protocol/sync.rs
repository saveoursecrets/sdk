include!(concat!(env!("OUT_DIR"), "/sync.rs"));

use super::{decode_uuid, encode_uuid, Error, Result, WireConvert};
use crate::sdk::{
    commit::Comparison,
    events::EventRecord,
    sync::{
        ChangeSet, Diff, MaybeDiff, Patch, SyncCompare, SyncDiff, SyncPacket,
        SyncStatus, UpdateSet,
    },
};
use indexmap::IndexMap;
use std::collections::HashMap;

impl WireConvert for SyncStatus {
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
            #[cfg(feature = "files")]
            files: value.files.map(|s| s.into()),
            folders: value
                .folders
                .into_iter()
                .map(|(k, v)| WireSyncFolderState {
                    folder_id: encode_uuid(k),
                    state: Some(v.into()),
                })
                .collect(),
        }
    }
}

impl WireConvert for Comparison {
    type Inner = WireComparison;
}

impl TryFrom<WireComparison> for Comparison {
    type Error = Error;

    fn try_from(value: WireComparison) -> Result<Self> {
        Ok(if let Some(true) = value.equal {
            Self::Equal
        } else if !value.contains.is_empty() {
            Self::Contains(
                value.contains.into_iter().map(|i| i as usize).collect(),
            )
        } else if let Some(true) = value.unknown {
            Self::Unknown
        } else {
            unreachable!()
        })
    }
}

impl From<Comparison> for WireComparison {
    fn from(value: Comparison) -> Self {
        match value {
            Comparison::Equal => WireComparison {
                equal: Some(true),
                contains: vec![],
                unknown: Some(false),
            },
            Comparison::Contains(indices) => WireComparison {
                equal: Some(false),
                contains: indices.into_iter().map(|i| i as u64).collect(),
                unknown: Some(false),
            },
            Comparison::Unknown => WireComparison {
                equal: Some(false),
                contains: vec![],
                unknown: Some(true),
            },
        }
    }
}

impl<T> WireConvert for Patch<T> {
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

impl<T> WireConvert for Diff<T> {
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

impl<T> WireConvert for MaybeDiff<T> {
    type Inner = WireMaybeDiff;
}

impl<T> TryFrom<WireMaybeDiff> for MaybeDiff<T>
where
    T: TryFrom<WireDiff, Error = Error>,
{
    type Error = Error;

    fn try_from(value: WireMaybeDiff) -> Result<Self> {
        if let Some(diff) = value.diff {
            Ok(Self::Diff(diff.inner.unwrap().try_into()?))
        } else if let Some(compare) = value.compare {
            let compare = if let Some(compare) = compare.inner {
                Some(compare.try_into()?)
            } else {
                None
            };
            Ok(Self::Compare(compare))
        } else {
            unreachable!()
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
                diff: Some(WireMaybeDiffHasDiff {
                    inner: Some(diff.into()),
                }),
                compare: None,
            },
            MaybeDiff::<T>::Compare(compare) => WireMaybeDiff {
                diff: None,
                compare: Some(WireMaybeDiffNeedsCompare {
                    inner: compare.map(|c| c.into()),
                }),
            },
        }
    }
}

impl WireConvert for ChangeSet {
    type Inner = WireChangeSet;
}

impl TryFrom<WireChangeSet> for ChangeSet {
    type Error = Error;

    fn try_from(value: WireChangeSet) -> Result<Self> {
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

impl From<ChangeSet> for WireChangeSet {
    fn from(value: ChangeSet) -> Self {
        Self {
            identity: Some(value.identity.into()),
            account: Some(value.account.into()),
            #[cfg(feature = "device")]
            device: Some(value.device.into()),
            #[cfg(feature = "files")]
            files: Some(value.files.into()),
            folders: value
                .folders
                .into_iter()
                .map(|(k, v)| WireSyncFolderPatch {
                    folder_id: encode_uuid(k),
                    patch: Some(v.into()),
                })
                .collect(),
        }
    }
}

impl WireConvert for UpdateSet {
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
            #[cfg(feature = "files")]
            files: value.files.map(|d| d.into()),
            folders: value
                .folders
                .into_iter()
                .map(|(k, v)| WireSyncFolderDiff {
                    folder_id: encode_uuid(k),
                    diff: Some(v.into()),
                })
                .collect(),
        }
    }
}

impl WireConvert for SyncDiff {
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
            #[cfg(feature = "files")]
            files: value.files.map(|d| d.into()),
            folders: value
                .folders
                .into_iter()
                .map(|(k, v)| WireSyncFolderMaybeDiff {
                    folder_id: encode_uuid(k),
                    maybe_diff: Some(v.into()),
                })
                .collect(),
        }
    }
}

impl WireConvert for SyncCompare {
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
            #[cfg(feature = "files")]
            files: value.files.map(|d| d.into()),
            folders: value
                .folders
                .into_iter()
                .map(|(k, v)| WireSyncFolderComparison {
                    folder_id: super::encode_uuid(k),
                    compare: Some(v.into()),
                })
                .collect(),
        }
    }
}

impl WireConvert for SyncPacket {
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
