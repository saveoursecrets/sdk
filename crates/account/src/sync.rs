//! Implements merging into a local account.
use crate::{Error, LocalAccount, Result};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::{AccountEventLog, DeviceEventLog, FolderEventLog};
use sos_core::{
    events::{
        patch::{AccountDiff, CheckedPatch, DeviceDiff, FolderDiff},
        WriteEvent,
    },
    VaultId,
};
use sos_sync::{
    ForceMerge, Merge, MergeOutcome, StorageEventLogs, SyncStorage,
};
use sos_vault::Summary;
use std::{collections::HashSet, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "files")]
use {sos_backend::FileEventLog, sos_core::events::patch::FileDiff};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StorageEventLogs for LocalAccount {
    type Error = Error;

    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        let storage = self.storage.read().await;
        Ok(storage.identity_log().await?)
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        let storage = self.storage.read().await;
        Ok(storage.account_log().await?)
    }

    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        let storage = self.storage.read().await;
        Ok(storage.device_log().await?)
    }

    #[cfg(feature = "files")]
    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        let storage = self.storage.read().await;
        Ok(storage.file_log().await?)
    }

    async fn folder_details(&self) -> Result<IndexSet<Summary>> {
        let storage = self.storage.read().await;
        Ok(storage.folder_details().await?)
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        let storage = self.storage.read().await;
        Ok(storage.folder_log(id).await?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ForceMerge for LocalAccount {
    async fn force_merge_identity(
        &mut self,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        let mut storage = self.storage.write().await;
        Ok(storage.force_merge_identity(diff, outcome).await?)
    }

    /// Force merge changes to the files event log.
    async fn force_merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        let mut storage = self.storage.write().await;
        Ok(storage.force_merge_folder(folder_id, diff, outcome).await?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Merge for LocalAccount {
    async fn merge_identity(
        &mut self,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        let mut storage = self.storage.write().await;
        Ok(storage.merge_identity(diff, outcome).await?)
    }

    async fn merge_account(
        &mut self,
        diff: AccountDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<(CheckedPatch, HashSet<VaultId>)> {
        let mut storage = self.storage.write().await;
        Ok(storage.merge_account(diff, outcome).await?)
    }

    async fn merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        let mut storage = self.storage.write().await;
        Ok(storage.merge_device(diff, outcome).await?)
    }

    #[cfg(feature = "files")]
    async fn merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        let mut storage = self.storage.write().await;
        Ok(storage.merge_files(diff, outcome).await?)
    }

    async fn merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<(CheckedPatch, Vec<WriteEvent>)> {
        let mut storage = self.storage.write().await;
        Ok(storage.merge_folder(folder_id, diff, outcome).await?)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SyncStorage for LocalAccount {
    fn is_client_storage(&self) -> bool {
        true
    }
}
