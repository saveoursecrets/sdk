include!(concat!(env!("OUT_DIR"), "/sync.rs"));

use super::{Error, Result, WireConvert};
use crate::sdk::{
    commit::Comparison,
    events::EventRecord,
    sync::{Diff, MaybeDiff, Patch, SyncStatus},
};
use binary_stream::futures::{Decodable, Encodable};
use indexmap::IndexMap;

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
                super::decode_uuid(&folder.folder_id)?,
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
                    folder_id: super::encode_uuid(k),
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

impl<T> WireConvert for Diff<T>
where
    T: Default + Encodable + Decodable,
{
    type Inner = WireDiff;
}

impl<T> TryFrom<WireDiff> for Diff<T>
where
    T: Default + Encodable + Decodable,
{
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

impl<T> From<Diff<T>> for WireDiff
where
    T: Default + Encodable + Decodable,
{
    fn from(value: Diff<T>) -> Self {
        Self {
            last_commit: value.last_commit.map(|c| c.into()),
            patch: Some(value.patch.into()),
            checkpoint: Some(value.checkpoint.into()),
        }
    }
}

// TODO: MaybeDiff
//
// TODO: ChangeSet
// TODO: UpdateSet
// TODO: SyncDiff
// TODO: SyncCompare
// TODO: SyncPacket

#[cfg(feature = "files")]
mod files {
    use super::{WireExternalFile, WireFileSet, WireFileTransfersSet};
    use crate::protocol::{
        decode_uuid, encode_uuid, Error, Result, WireConvert,
    };
    use crate::sdk::{
        storage::files::{
            ExternalFile, ExternalFileName, FileSet, FileTransfersSet,
        },
        vault::{secret::SecretId, VaultId},
    };
    use indexmap::IndexSet;

    impl WireConvert for ExternalFile {
        type Inner = WireExternalFile;
    }

    impl TryFrom<WireExternalFile> for ExternalFile {
        type Error = Error;

        fn try_from(value: WireExternalFile) -> Result<Self> {
            let folder_id = decode_uuid(&value.folder_id)?;
            let secret_id = decode_uuid(&value.secret_id)?;
            let file_name: [u8; 32] =
                value.file_name.as_slice().try_into()?;
            Ok(Self::new(folder_id, secret_id, file_name.into()))
        }
    }

    impl From<ExternalFile> for WireExternalFile {
        fn from(value: ExternalFile) -> Self {
            let (folder_id, secret_id, file_name): (
                VaultId,
                SecretId,
                ExternalFileName,
            ) = value.into();
            Self {
                folder_id: encode_uuid(folder_id),
                secret_id: encode_uuid(secret_id),
                file_name: file_name.as_ref().to_vec(),
            }
        }
    }

    impl WireConvert for FileSet {
        type Inner = WireFileSet;
    }

    impl TryFrom<WireFileSet> for FileSet {
        type Error = Error;

        fn try_from(value: WireFileSet) -> Result<Self> {
            let mut files = IndexSet::new();
            for file in value.files {
                files.insert(file.try_into()?);
            }
            Ok(Self(files))
        }
    }

    impl From<FileSet> for WireFileSet {
        fn from(value: FileSet) -> Self {
            Self {
                files: value.0.into_iter().map(|f| f.into()).collect(),
            }
        }
    }

    impl WireConvert for FileTransfersSet {
        type Inner = WireFileTransfersSet;
    }

    impl TryFrom<WireFileTransfersSet> for FileTransfersSet {
        type Error = Error;

        fn try_from(value: WireFileTransfersSet) -> Result<Self> {
            let uploads: FileSet = value.uploads.unwrap().try_into()?;
            let downloads: FileSet = value.downloads.unwrap().try_into()?;
            Ok(Self { uploads, downloads })
        }
    }

    impl From<FileTransfersSet> for WireFileTransfersSet {
        fn from(value: FileTransfersSet) -> Self {
            Self {
                uploads: Some(value.uploads.into()),
                downloads: Some(value.downloads.into()),
            }
        }
    }
}
