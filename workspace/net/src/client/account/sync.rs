//! Adds sync capability to network account.
use crate::client::{NetworkAccount, RemoteSync, SyncError, SyncOptions};
use async_trait::async_trait;
use sos_sdk::{
    events::{AccountEventLog, FolderEventLog},
    sync::{Origin, SyncClient, SyncStatus, SyncStorage},
    vault::VaultId,
    Result,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "device")]
use sos_sdk::events::DeviceEventLog;

#[cfg(feature = "files")]
use sos_sdk::events::FileEventLog;

impl NetworkAccount {
    /// Sync status for remote servers.
    pub async fn server_status(
        &self,
        options: &SyncOptions,
    ) -> HashMap<Origin, crate::client::Result<Option<SyncStatus>>> {
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
        let _ = self.sync_lock.lock().await;
        let mut errors = Vec::new();
        let remotes = self.remotes.read().await;

        for (origin, remote) in &*remotes {
            let sync_remote = options.origins.is_empty()
                || options.origins.contains(origin);

            if sync_remote {
                if let Some(e) = remote.sync_with_options(options).await {
                    match e {
                        SyncError::One(e) => errors.push((origin.clone(), e)),
                        SyncError::Multiple(mut errs) => {
                            errors.append(&mut errs)
                        }
                    }
                }
            }
        }
        if errors.is_empty() {
            None
        } else {
            for error in &errors {
                tracing::error!(error = ?error);
            }
            Some(SyncError::Multiple(errors))
        }
    }

    async fn sync_file_transfers(
        &self,
        options: &SyncOptions,
    ) -> Option<SyncError> {
        todo!("sync_file_transfers");
    }

    async fn patch_devices(&self) -> Option<SyncError> {
        let _ = self.sync_lock.lock().await;
        let mut errors = Vec::new();
        let remotes = self.remotes.read().await;

        for (origin, remote) in &*remotes {
            if let Some(e) = remote.patch_devices().await {
                match e {
                    SyncError::One(e) => errors.push((origin.clone(), e)),
                    SyncError::Multiple(mut errs) => errors.append(&mut errs),
                }
            }
        }
        if errors.is_empty() {
            None
        } else {
            for error in &errors {
                tracing::error!(error = ?error);
            }
            Some(SyncError::Multiple(errors))
        }
    }
}

#[async_trait]
impl SyncStorage for NetworkAccount {
    async fn sync_status(&self) -> Result<SyncStatus> {
        let account = self.account.lock().await;
        account.sync_status().await
    }

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
