use super::ClientFileStorage;
use crate::{ClientFolderStorage, Error, Result};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::{
    AccountEventLog, DeviceEventLog, FolderEventLog, StorageError,
};
use sos_core::VaultId;
use sos_sync::StorageEventLogs;
use sos_vault::Summary;
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(feature = "files")]
use sos_backend::FileEventLog;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StorageEventLogs for ClientFileStorage {
    type Error = Error;

    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        Ok(self.identity_log.clone())
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        Ok(self.account_log.clone())
    }

    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        Ok(self.device_log.clone())
    }

    #[cfg(feature = "files")]
    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        Ok(self.file_log.clone())
    }

    async fn folder_details(&self) -> Result<IndexSet<Summary>> {
        let folders = self.list_folders();
        Ok(folders.into_iter().cloned().collect())
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        let folder = self
            .folders
            .get(id)
            .ok_or(StorageError::CacheNotAvailable(*id))?;
        Ok(folder.event_log())
    }
}
