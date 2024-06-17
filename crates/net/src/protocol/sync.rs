include!(concat!(env!("OUT_DIR"), "/sync.rs"));

use super::{Error, Result, WireConvert};
use crate::sdk::{
    commit::Comparison,
    sync::{Patch, SyncStatus},
};
use binary_stream::futures::{Decodable, Encodable};
use indexmap::IndexMap;
use sos_sdk::events::EventRecord;

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
                super::decode_uuid(Some(folder.folder_id))?,
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
                    folder_id: super::encode_uuid(k).unwrap(),
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

impl<T> WireConvert for Patch<T>
where
    T: Default + Encodable + Decodable,
{
    type Inner = WirePatch;
}

impl<T> TryFrom<WirePatch> for Patch<T>
where
    T: Default + Encodable + Decodable,
{
    type Error = Error;

    fn try_from(value: WirePatch) -> Result<Self> {
        let mut records = Vec::with_capacity(value.records.len());
        for record in value.records {
            records.push(record.try_into()?);
        }
        Ok(Self::new(records))
    }
}

impl<T> From<Patch<T>> for WirePatch
where
    T: Default + Encodable + Decodable,
{
    fn from(value: Patch<T>) -> Self {
        let records: Vec<EventRecord> = value.into();
        Self {
            records: records.into_iter().map(|r| r.into()).collect(),
        }
    }
}

// TODO: Patch
// TODO: Diff
// TODO: ChangeSet
// TODO: UpdateSet
// TODO: MaybeDiff
// TODO: SyncDiff
// TODO: SyncCompare
