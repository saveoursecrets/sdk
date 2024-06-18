//! Adds sync capability to network account.
use crate::{
    client::{NetworkAccount, RemoteSync, SyncClient, SyncError},
    sync::{
        FileSet, FileTransfersSet, Origin, SyncOptions, SyncStatus,
        SyncStorage, UpdateSet,
    },
};
use async_trait::async_trait;
use sos_sdk::{
    events::{AccountEventLog, FolderEventLog},
    storage::StorageEventLogs,
    vault::VaultId,
    Result,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "device")]
use sos_sdk::events::DeviceEventLog;

#[cfg(feature = "files")]
use sos_sdk::events::FileEventLog;

/// Server status for all remote origins.
pub type ServerStatus = HashMap<Origin, crate::client::Result<SyncStatus>>;

/// Transfer status for all remote origins.
pub type TransferStatus =
    HashMap<Origin, crate::client::Result<FileTransfersSet>>;

impl NetworkAccount {
    /// Sync status for remote servers.
    pub async fn server_status(&self, options: &SyncOptions) -> ServerStatus {
        if self.offline {
            tracing::warn!("offline mode active, ignoring server status");
            return Default::default();
        }

        let remotes = self.remotes.read().await;
        let mut server_status = HashMap::new();
        for (origin, remote) in &*remotes {
            let sync_remote = options.origins.is_empty()
                || options.origins.contains(origin);

            if sync_remote {
                match remote.client.sync_status().await {
                    Ok(status) => {
                        server_status.insert(origin.clone(), Ok(status));
                    }
                    Err(e) => {
                        server_status.insert(origin.clone(), Err(e));
                    }
                }
            }
        }
        server_status
    }

    /// Transfer status for remote servers.
    #[cfg(feature = "files")]
    pub async fn transfer_status(
        &self,
        options: &SyncOptions,
    ) -> Result<TransferStatus> {
        let external_files = self.canonical_files().await?;
        let local_files = FileSet(external_files);

        let remotes = self.remotes.read().await;
        let mut transfer_status = HashMap::new();
        for (origin, remote) in &*remotes {
            let sync_remote = options.origins.is_empty()
                || options.origins.contains(origin);

            if sync_remote {
                match remote.client.compare_files(local_files.clone()).await {
                    Ok(status) => {
                        transfer_status.insert(origin.clone(), Ok(status));
                    }
                    Err(e) => {
                        transfer_status.insert(origin.clone(), Err(e));
                    }
                }
            }
        }
        Ok(transfer_status)
    }
}

#[async_trait]
impl RemoteSync for NetworkAccount {
    async fn sync(&self) -> Option<SyncError> {
        self.sync_with_options(&Default::default()).await
    }

    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> Option<SyncError> {
        if self.offline {
            tracing::warn!("offline mode active, ignoring sync");
            return None;
        }

        let _ = self.sync_lock.lock().await;
        let mut maybe_error: SyncError = Default::default();
        let remotes = self.remotes.read().await;

        for (origin, remote) in &*remotes {
            let sync_remote = options.origins.is_empty()
                || options.origins.contains(origin);

            if sync_remote {
                if let Some(mut e) = remote.sync_with_options(options).await {
                    maybe_error.errors.append(&mut e.errors);
                }
            }
        }
        maybe_error.into_option()
    }

    async fn sync_file_transfers(
        &self,
        options: &SyncOptions,
    ) -> Option<SyncError> {
        if self.offline {
            tracing::warn!(
                "offline mode active, ignoring sync file transfers"
            );
            return None;
        }

        let _ = self.sync_lock.lock().await;
        let mut maybe_error: SyncError = Default::default();
        let remotes = self.remotes.read().await;

        for (origin, remote) in &*remotes {
            let sync_remote = options.origins.is_empty()
                || options.origins.contains(origin);

            if sync_remote {
                if let Some(mut e) = remote.sync_file_transfers(options).await
                {
                    maybe_error.errors.append(&mut e.errors);
                }
            }
        }
        maybe_error.into_option()
    }

    async fn force_update(
        &self,
        account_data: UpdateSet,
        options: &SyncOptions,
    ) -> Option<SyncError> {
        if self.offline {
            tracing::warn!("offline mode active, ignoring force update");
            return None;
        }

        let _ = self.sync_lock.lock().await;
        let mut maybe_error: SyncError = Default::default();
        let remotes = self.remotes.read().await;

        for (origin, remote) in &*remotes {
            let sync_remote = options.origins.is_empty()
                || options.origins.contains(origin);

            if sync_remote {
                if let Some(mut e) =
                    remote.force_update(account_data.clone(), options).await
                {
                    maybe_error.errors.append(&mut e.errors);
                }
            }
        }
        maybe_error.into_option()
    }
}

#[async_trait]
impl StorageEventLogs for NetworkAccount {
    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        let account = self.account.lock().await;
        account.identity_log().await
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        let account = self.account.lock().await;
        account.account_log().await
    }

    #[cfg(feature = "device")]
    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        let account = self.account.lock().await;
        account.device_log().await
    }

    #[cfg(feature = "files")]
    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        let account = self.account.lock().await;
        account.file_log().await
    }

    async fn folder_identifiers(&self) -> Result<Vec<VaultId>> {
        let account = self.account.lock().await;
        account.folder_identifiers().await
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        let account = self.account.lock().await;
        account.folder_log(id).await
    }
}

#[async_trait]
impl SyncStorage for NetworkAccount {
    async fn sync_status(&self) -> Result<SyncStatus> {
        let account = self.account.lock().await;
        account.sync_status().await
    }
}
