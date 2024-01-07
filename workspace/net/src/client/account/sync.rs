//! Adds sync capability to network account.
use crate::client::{NetworkAccount, RemoteSync, SyncError, SyncOptions};
use async_trait::async_trait;
use sos_sdk::{
    events::{AccountEventLog, FolderEventLog},
    sync::{SyncStatus, SyncStorage},
    vault::VaultId,
    Result,
};
use std::{any::Any, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "device")]
use sos_sdk::events::DeviceEventLog;

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

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
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
