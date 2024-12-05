//! Adds sync capability to network account.
use crate::{
    protocol::{
        AccountSync, Merge, Origin, RemoteSync, SyncClient, SyncOptions,
        SyncResult, SyncStatus, SyncStorage, UpdateSet,
    },
    sdk::{
        events::{AccountEventLog, FolderEventLog},
        prelude::{Account, CommitState},
        storage::StorageEventLogs,
        vault::{Summary, VaultId},
        Result,
    },
    NetworkAccount,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_protocol::MergeOutcome;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;

use sos_sdk::{
    commit::Comparison,
    events::{
        AccountDiff, CheckedPatch, DeviceDiff, DeviceEventLog, FolderDiff,
        WriteEvent,
    },
};

#[cfg(feature = "files")]
use crate::{
    protocol::transfer::{FileSet, FileSyncClient, FileTransfersSet},
    sdk::events::{FileDiff, FileEventLog},
};

/// Server status for all remote origins.
pub type ServerStatus = HashMap<Origin, crate::Result<SyncStatus>>;

/// Transfer status for all remote origins.
#[cfg(feature = "files")]
pub type TransferStatus = HashMap<Origin, crate::Result<FileTransfersSet>>;

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
                match remote.client.sync_status(self.address()).await {
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
impl AccountSync for NetworkAccount {
    type Error = crate::Error;

    async fn sync(&self) -> SyncResult<Self::Error> {
        self.sync_with_options(&Default::default()).await
    }

    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> SyncResult<Self::Error> {
        let mut result = SyncResult::default();
        if self.offline {
            tracing::warn!("offline mode active, ignoring sync");
            return result;
        }

        let _ = self.sync_lock.lock().await;
        let remotes = self.remotes.read().await;

        for (origin, remote) in &*remotes {
            let sync_remote = options.origins.is_empty()
                || options.origins.contains(origin);

            if !sync_remote {
                tracing::warn!(origin = %origin, "skip_sync::sync_with_options");
                continue;
            }

            let remote_result = remote.sync_with_options(options).await;
            result.remotes.push(remote_result);
        }
        result
    }

    #[cfg(feature = "files")]
    async fn sync_file_transfers(
        &self,
        options: &SyncOptions,
    ) -> SyncResult<Self::Error> {
        let mut result = SyncResult::default();
        if self.offline {
            tracing::warn!(
                "offline mode active, ignoring sync file transfers"
            );
            return result;
        }

        let _ = self.sync_lock.lock().await;
        let remotes = self.remotes.read().await;

        for (origin, remote) in &*remotes {
            let sync_remote = options.origins.is_empty()
                || options.origins.contains(origin);

            if !sync_remote {
                tracing::warn!(origin = %origin, "skip_sync::sync_file_transfers");
                continue;
            }

            let remote_result = remote.sync_file_transfers().await;
            result.remotes.push(remote_result);
        }
        result
    }

    async fn force_update(
        &self,
        account_data: UpdateSet,
        options: &SyncOptions,
    ) -> SyncResult<Self::Error> {
        let mut result = SyncResult::default();
        if self.offline {
            tracing::warn!("offline mode active, ignoring force update");
            return result;
        }

        let _ = self.sync_lock.lock().await;
        let remotes = self.remotes.read().await;

        for (origin, remote) in &*remotes {
            let sync_remote = options.origins.is_empty()
                || options.origins.contains(origin);

            if !sync_remote {
                tracing::warn!(origin = %origin, "skip_sync::force_update");
                continue;
            }

            let remote_result =
                remote.force_update(account_data.clone()).await;
            result.remotes.push(remote_result);
        }
        result
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

    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        let account = self.account.lock().await;
        account.device_log().await
    }

    #[cfg(feature = "files")]
    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        let account = self.account.lock().await;
        account.file_log().await
    }

    async fn folder_details(&self) -> Result<IndexSet<Summary>> {
        let account = self.account.lock().await;
        account.folder_details().await
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
    fn is_client_storage(&self) -> bool {
        true
    }

    async fn sync_status(&self) -> Result<SyncStatus> {
        let account = self.account.lock().await;
        account.sync_status().await
    }
}

#[async_trait]
impl Merge for NetworkAccount {
    async fn merge_identity(
        &mut self,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        let mut account = self.account.lock().await;
        Ok(account.merge_identity(diff, outcome).await?)
    }

    async fn compare_identity(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let account = self.account.lock().await;
        Ok(account.compare_identity(state).await?)
    }

    async fn merge_account(
        &mut self,
        diff: AccountDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<(CheckedPatch, HashSet<VaultId>)> {
        let mut account = self.account.lock().await;
        Ok(account.merge_account(diff, outcome).await?)
    }

    async fn compare_account(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let account = self.account.lock().await;
        Ok(account.compare_account(state).await?)
    }

    async fn merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        let mut account = self.account.lock().await;
        Ok(account.merge_device(diff, outcome).await?)
    }

    async fn compare_device(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let account = self.account.lock().await;
        Ok(account.compare_device(state).await?)
    }

    #[cfg(feature = "files")]
    async fn merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        let mut account = self.account.lock().await;
        Ok(account.merge_files(diff, outcome).await?)
    }

    #[cfg(feature = "files")]
    async fn compare_files(&self, state: &CommitState) -> Result<Comparison> {
        let account = self.account.lock().await;
        Ok(account.compare_files(state).await?)
    }

    async fn merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<(CheckedPatch, Vec<WriteEvent>)> {
        let mut account = self.account.lock().await;
        Ok(account.merge_folder(folder_id, diff, outcome).await?)
    }

    async fn compare_folder(
        &self,
        folder_id: &VaultId,
        state: &CommitState,
    ) -> Result<Comparison> {
        let account = self.account.lock().await;
        Ok(account.compare_folder(folder_id, state).await?)
    }
}
