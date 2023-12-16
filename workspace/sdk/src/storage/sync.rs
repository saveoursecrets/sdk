//! Synchronization helpers.
use crate::{
    encode,
    events::{
        AccountEvent, EventLogExt, EventReducer, FolderEventLog, WriteEvent,
        AccountEventLog,
    },
    storage::{ServerStorage, ClientStorage},
    sync::{
        AccountDiff, ChangeSet, FolderDiff, FolderPatch, SyncDiff, SyncStatus,
        SyncStorage,
    },
    vault::VaultId,
    vfs, Error, Paths, Result,
};
use async_trait::async_trait;
use tokio::sync::RwLock;
use std::{collections::HashMap, sync::Arc};

impl ServerStorage {
    /// Create a new vault file on disc and the associated
    /// event log.
    ///
    /// If a vault file already exists it is overwritten if an
    /// event log exists it is truncated.
    ///
    /// Intended to be used by a server to create the identity
    /// vault and event log when a new account is created.
    pub async fn initialize_account(
        paths: &Paths,
        identity_patch: &FolderPatch,
    ) -> Result<FolderEventLog> {
        let events: Vec<&WriteEvent> = identity_patch.into();

        let mut event_log =
            FolderEventLog::new(paths.identity_events()).await?;
        event_log.clear().await?;
        event_log.apply(events).await?;

        let vault = EventReducer::new()
            .reduce(&event_log)
            .await?
            .build(false)
            .await?;

        let buffer = encode(&vault).await?;
        vfs::write(paths.identity_vault(), buffer).await?;

        Ok(event_log)
    }

    /// Import an account from a change set of event logs.
    ///
    /// Does not prepare the identity vault event log
    /// which should be done by calling `initialize_account()`
    /// before creating new storage.
    ///
    /// Intended to be used on a server to create a new
    /// account from a collection of patches.
    pub async fn import_account(
        &mut self,
        account_data: &ChangeSet,
    ) -> Result<()> {
        {
            let mut writer = self.account_log.write().await;
            writer.patch_unchecked(&account_data.account).await?;
        }

        for (id, folder) in &account_data.folders {
            let vault_path = self.paths.vault_path(id);
            let events_path = self.paths.event_log_path(id);

            let mut event_log = FolderEventLog::new(events_path).await?;
            event_log.patch_unchecked(folder).await?;

            let vault = EventReducer::new()
                .reduce(&event_log)
                .await?
                .build(false)
                .await?;

            let summary = vault.summary().clone();

            let buffer = encode(&vault).await?;
            vfs::write(vault_path, buffer).await?;

            self.cache_mut().insert(*id, event_log);
        }

        Ok(())
    }


    async fn replay_identity_events(
        &mut self,
        diff: &FolderDiff,
    ) -> Result<usize> {
        let mut writer = self.identity_log.write().await;
        writer.patch_checked(&diff.before, &diff.patch).await?;
        Ok(diff.patch.len())
    }

    async fn replay_account_events(
        &mut self,
        diff: &AccountDiff,
    ) -> Result<usize> {
        for event in diff.patch.iter() {
            match &event {
                AccountEvent::CreateFolder(id, buf)
                | AccountEvent::UpdateFolder(id, buf)
                | AccountEvent::CompactFolder(id, buf)
                | AccountEvent::ChangeFolderPassword(id, buf) => {
                    self.import_folder(id, buf).await?;
                }
                AccountEvent::RenameFolder(id, name) => {
                    let id = self.cache.keys().find(|&fid| fid == id).cloned();
                    if let Some(id) = &id{
                        self.rename_folder(id, name).await?;
                    }
                }
                AccountEvent::DeleteFolder(id) => {
                    let id = self.cache.keys().find(|&fid| fid == id).cloned();
                    if let Some(id) = &id{
                        self.delete_folder(id).await?;
                    }
                }
                _ => {
                    println!("todo! : apply other account events")
                }
            }
        }

        Ok(diff.patch.len())
    }

    async fn replay_folder_events(
        &mut self,
        folders: &HashMap<VaultId, FolderDiff>,
    ) -> Result<usize> {
        let mut num_changes = 0;
        for (id, diff) in folders {
            let log = self
                .cache
                .get_mut(id)
                .ok_or_else(|| Error::CacheNotAvailable(*id))?;

            log.patch_checked(&diff.before, &diff.patch).await?;
            num_changes += diff.patch.len();
        }
        Ok(num_changes)
    }

    /// Merge a diff into this storage.
    pub async fn merge_diff(
        &mut self,
        diff: &SyncDiff,
    ) -> Result<usize> {
        let mut num_changes = 0;

        if let Some(diff) = &diff.identity {
            num_changes += self.replay_identity_events(diff).await?;
        }

        if let Some(diff) = &diff.account {
            num_changes += self.replay_account_events(diff).await?;
        }

        num_changes +=
            self.replay_folder_events(&diff.folders).await?;

        Ok(num_changes)
    }
}

#[async_trait]
impl SyncStorage for ServerStorage {
    async fn sync_status(&self) -> Result<SyncStatus> {
        let identity = {
            let reader = self.identity_log.read().await;
            reader.tree().commit_state()?
        };

        let account = {
            let reader = self.account_log.read().await;
            reader.tree().commit_state()?
        };

        let mut folders = HashMap::new();
        for (id, event_log) in &self.cache {
            let last_commit =
                event_log.tree().last_commit().ok_or(Error::NoRootCommit)?;
            let head = event_log.tree().head()?;
            folders.insert(*id, (last_commit, head));
        }
        Ok(SyncStatus {
            identity,
            account,
            folders,
        })
    }

    fn identity_log(&self) -> Arc<RwLock<FolderEventLog>> {
        Arc::clone(&self.identity_log)
    }

    fn account_log(&self) -> Arc<RwLock<AccountEventLog>> {
        Arc::clone(&self.account_log)
    }

    fn folder_log(&self, id: &VaultId) -> Result<&FolderEventLog> {
        self
            .cache
            .get(id)
            .ok_or(Error::CacheNotAvailable(*id))
    }
}

impl ClientStorage {

    /// Change set of all event logs.
    ///
    /// Used by network aware implementations to send
    /// account information to a server.
    pub async fn change_set(&self) -> Result<ChangeSet> {
        let identity = {
            let reader = self.identity_log.read().await;
            reader.diff(None).await?
        };

        let account = {
            let reader = self.account_log.read().await;
            reader.diff(None).await?
        };

        let mut folders = HashMap::new();
        for summary in self.state.summaries() {
            let folder_log = self
                .cache
                .get(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            folders.insert(*summary.id(), folder_log.diff(None).await?);
        }

        Ok(ChangeSet {
            identity,
            account,
            folders,
        })
    }

    async fn replay_identity_events(
        &mut self,
        diff: &FolderDiff,
    ) -> Result<usize> {
        todo!("client replay identity events");
    }

    async fn replay_account_events(
        &mut self,
        diff: &AccountDiff,
    ) -> Result<usize> {
        todo!("client replay account events");
    }

    async fn replay_folder_events(
        &mut self,
        folders: &HashMap<VaultId, FolderDiff>,
    ) -> Result<usize> {
        todo!("client replay folder events");
    }

    /// Merge a diff into this storage.
    pub async fn merge_diff(
        &mut self,
        diff: &SyncDiff,
    ) -> Result<usize> {
        let mut num_changes = 0;

        if let Some(diff) = &diff.identity {
            num_changes += self.replay_identity_events(diff).await?;
        }

        if let Some(diff) = &diff.account {
            num_changes += self.replay_account_events(diff).await?;
        }

        num_changes +=
            self.replay_folder_events(&diff.folders).await?;

        Ok(num_changes)
    }

    /*
    /// Apply identity-level events to this storage
    async fn replay_identity_events(
        &mut self,
        diff: &FolderDiff,
    ) -> Result<()> {
        for event in diff.patch.iter() {
            match event {
                WriteEvent::CreateSecret(secret_id, vault_commit) => {
                }
                WriteEvent::UpdateSecret(secret_id, vault_commit) => {
                }
                WriteEvent::SetVaultName(name) => {
                }
                WriteEvent::SetVaultMeta(meta) => {
                }
                WriteEvent::DeleteSecret(secret_id) => {
                }
                _ => {} // Ignore CreateVault and Noop
            }
        }
        Ok(())
    }

    /// Apply account-level events to this storage
    async fn replay_account_events(
        &mut self,
        diff: &AccountDiff,
    ) -> Result<()> {
        for event in diff.patch.iter() {
            match &event {
                AccountEvent::CreateFolder(_, buf)
                | AccountEvent::UpdateFolder(_, buf)
                | AccountEvent::CompactFolder(_, buf)
                | AccountEvent::ChangeFolderPassword(_, buf) => {
                    self.import_folder(buf, None).await?;
                }
                AccountEvent::RenameFolder(id, name) => {
                    let summary = self.find(|s| s.id() == id).cloned();
                    if let Some(summary) = &summary {
                        self.rename_folder(summary, name).await?;
                    }
                }
                AccountEvent::DeleteFolder(id) => {
                    let summary = self.find(|s| s.id() == id).cloned();
                    if let Some(summary) = &summary {
                        self.delete_folder(summary).await?;
                    }
                }
                _ => {
                    println!("todo! : apply other account events")
                }
            }
        }

        Ok(())
    }

    /// Apply folder-level events to this storage
    async fn replay_folder_events(
        &mut self,
        id: &VaultId,
        diff: &FolderDiff,
    ) -> Result<()> {
        for event in diff.patch.iter() {
            match event {
                WriteEvent::CreateSecret(secret_id, vault_commit) => {
                }
                WriteEvent::UpdateSecret(secret_id, vault_commit) => {
                }
                WriteEvent::SetVaultName(name) => {
                    let summary = self.find(|s| s.id() == id).cloned();
                    if let Some(summary) = &summary {
                        self.rename_folder(summary, name).await?;
                    }
                }
                WriteEvent::SetVaultMeta(meta) => {
                }
                WriteEvent::DeleteSecret(secret_id) => {
                    let summary = self.find(|s| s.id() == id).cloned();
                    if let Some(summary) = summary {
                        self.delete_secret(secret_id, summary.into()).await?;
                    }
                }
                _ => {} // Ignore CreateVault and Noop
            }
        }

        Ok(())
    }
    */
}

#[async_trait]
impl SyncStorage for ClientStorage {

    async fn sync_status(&self) -> Result<SyncStatus> {
        let identity = {
            let reader = self.identity_log.read().await;
            reader.tree().commit_state()?
        };

        let account = {
            let reader = self.account_log.read().await;
            reader.tree().commit_state()?
        };

        let summaries = self.state.summaries();
        let mut folders = HashMap::new();
        for summary in summaries {
            let event_log = self
                .cache
                .get(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;

            let last_commit =
                event_log.tree().last_commit().ok_or(Error::NoRootCommit)?;
            let head = event_log.tree().head()?;
            folders.insert(*summary.id(), (last_commit, head));
        }
        Ok(SyncStatus {
            identity,
            account,
            folders,
        })
    }

    fn identity_log(&self) -> Arc<RwLock<FolderEventLog>> {
        Arc::clone(&self.identity_log)
    }

    fn account_log(&self) -> Arc<RwLock<AccountEventLog>> {
        Arc::clone(&self.account_log)
    }

    fn folder_log(&self, id: &VaultId) -> Result<&FolderEventLog> {
        self
            .cache
            .get(id)
            .ok_or(Error::CacheNotAvailable(*id))
    }
}
