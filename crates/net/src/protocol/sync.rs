include!(concat!(env!("OUT_DIR"), "/sync.rs"));

use super::{Error, Result};
use crate::sdk::sync::SyncStatus;
use indexmap::IndexMap;

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
