use super::account::Account;
use crate::{
    events::{AccountEventLog, EventLogExt, FolderEventLog},
    sync::{
        AccountDiff, CheckedPatch, FolderDiff, SyncDiff, SyncStatus,
        SyncStorage,
    },
    vault::VaultId,
    Error, Result,
};
use async_trait::async_trait;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

impl<D> Account<D> {
    /// Merge a diff into this account.
    pub async fn merge_diff(&mut self, diff: &SyncDiff) -> Result<usize> {
        let mut num_changes = 0;

        if let Some(diff) = &diff.identity {
            num_changes += self.merge_identity(diff).await?;
        }

        if let Some(diff) = &diff.account {
            num_changes += self.merge_account(diff).await?;
        }

        num_changes += self.merge_folders(&diff.folders).await?;

        Ok(num_changes)
    }

    async fn merge_identity(&mut self, diff: &FolderDiff) -> Result<usize> {
        self.user_mut()?.identity_mut()?.merge_diff(diff).await?;
        Ok(diff.patch.len())
    }

    async fn merge_account(&mut self, diff: &AccountDiff) -> Result<usize> {
        todo!("client replay account events");
    }

    async fn merge_folders(
        &mut self,
        folders: &HashMap<VaultId, FolderDiff>,
    ) -> Result<usize> {
        todo!("client replay folder events");
    }
}

#[async_trait]
impl<D> SyncStorage for Account<D> {
    async fn sync_status(&self) -> Result<SyncStatus> {
        let storage = self.storage()?;
        let storage = storage.read().await;
        let summaries = storage.list_folders().to_vec();

        let identity = {
            let reader = storage.identity_log.read().await;
            reader.tree().commit_state()?
        };

        let account = {
            let reader = storage.account_log.read().await;
            reader.tree().commit_state()?
        };

        let mut folders = HashMap::new();
        for summary in &summaries {
            let folder = storage
                .cache()
                .get(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;

            let commit_state = folder.commit_state().await?;
            folders.insert(*summary.id(), commit_state);
        }
        Ok(SyncStatus {
            identity,
            account,
            folders,
        })
    }

    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        let storage = self.storage()?;
        let storage = storage.read().await;
        Ok(Arc::clone(&storage.identity_log))
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        let storage = self.storage()?;
        let storage = storage.read().await;
        Ok(Arc::clone(&storage.account_log))
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        let storage = self.storage()?;
        let storage = storage.read().await;
        let folder = storage
            .cache()
            .get(id)
            .ok_or(Error::CacheNotAvailable(*id))?;
        Ok(folder.event_log())
    }
}
