//! Folder storage backed by the file system.
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_core::VaultId;
use sos_sdk::{
    events::{AccountEventLog, FolderEventLog},
    vault::Summary,
};
use std::sync::Arc;
use tokio::sync::RwLock;

use sos_sdk::events::DeviceEventLog;

#[cfg(feature = "files")]
use {sos_core::ExternalFile, sos_sdk::events::FileEventLog};

/// References to the storage event logs.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait StorageEventLogs {
    type Error: std::error::Error
        + From<sos_sdk::Error>
        + Send
        + Sync
        + 'static;

    /// Clone of the identity log.
    async fn identity_log(
        &self,
    ) -> Result<Arc<RwLock<FolderEventLog>>, Self::Error>;

    /// Clone of the account log.
    async fn account_log(
        &self,
    ) -> Result<Arc<RwLock<AccountEventLog>>, Self::Error>;

    /// Clone of the device log.
    async fn device_log(
        &self,
    ) -> Result<Arc<RwLock<DeviceEventLog>>, Self::Error>;

    /// Clone of the file log.
    #[cfg(feature = "files")]
    async fn file_log(
        &self,
    ) -> Result<Arc<RwLock<FileEventLog>>, Self::Error>;

    /// Canonical collection of files reduced from the file event log.
    #[cfg(feature = "files")]
    async fn canonical_files(
        &self,
    ) -> Result<IndexSet<ExternalFile>, Self::Error> {
        use sos_sdk::events::FileReducer;
        let files = self.file_log().await?;
        let event_log = files.read().await;

        // Canonical list of external files.
        let reducer = FileReducer::new(&event_log);
        Ok(reducer.reduce(None).await?)
    }

    /// Folders managed by this storage.
    ///
    /// Built from the in-memory list of folders.
    async fn folder_details(&self) -> Result<IndexSet<Summary>, Self::Error>;

    /// Folder event log.
    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>, Self::Error>;
}
