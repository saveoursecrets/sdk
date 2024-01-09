//! Synchronization helpers.
use crate::{
    encode,
    events::{
        AccountEvent, AccountEventLog, EventLogExt, EventReducer,
        FolderEventLog, LogEvent, WriteEvent,
    },
    storage::ServerStorage,
    sync::{
        AccountDiff, ChangeSet, CheckedPatch, FolderDiff, FolderPatch,
        SyncDiff, SyncStatus, SyncStorage,
    },
    vault::VaultId,
    vfs, Error, Paths, Result,
};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{span, Level};

#[cfg(feature = "device")]
use crate::{
    events::{DeviceEventLog, DeviceReducer},
    sync::DeviceDiff,
};

#[cfg(feature = "files")]
use crate::{events::FileEventLog, sync::FileDiff};

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

        #[cfg(feature = "device")]
        {
            let mut writer = self.device_log.write().await;
            writer.patch_unchecked(&account_data.device).await?;
            let reducer = DeviceReducer::new(&*writer);
            self.devices = reducer.reduce().await?;
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

            let buffer = encode(&vault).await?;
            vfs::write(vault_path, buffer).await?;

            self.cache_mut()
                .insert(*id, Arc::new(RwLock::new(event_log)));
        }

        Ok(())
    }

    /// Merge a diff into this storage.
    pub async fn merge(&mut self, diff: &SyncDiff) -> Result<usize> {
        let span = span!(Level::DEBUG, "merge_server");
        let _enter = span.enter();

        let mut num_changes = 0;

        if let Some(diff) = &diff.identity {
            num_changes += self.merge_identity(diff).await?;
        }

        if let Some(diff) = &diff.account {
            num_changes += self.merge_account(diff).await?;
        }

        #[cfg(feature = "device")]
        if let Some(diff) = &diff.device {
            num_changes += self.merge_device(diff).await?;
        }

        num_changes += self.merge_folders(&diff.folders).await?;

        tracing::debug!(num_changes = %num_changes, "merge complete");

        Ok(num_changes)
    }

    async fn merge_identity(&mut self, diff: &FolderDiff) -> Result<usize> {
        let mut writer = self.identity_log.write().await;
        tracing::debug!(
            before = ?diff.before,
            num_events = diff.patch.len(),
            "identity",
        );
        writer.patch_checked(&diff.before, &diff.patch).await?;
        Ok(diff.patch.len())
    }

    async fn merge_account(&mut self, diff: &AccountDiff) -> Result<usize> {
        tracing::debug!(
            before = ?diff.before,
            num_events = diff.patch.len(),
            "account",
        );

        let checked_patch = {
            let mut event_log = self.account_log.write().await;
            event_log.patch_checked(&diff.before, &diff.patch).await?
        };

        if let CheckedPatch::Success(_, _) = &checked_patch {
            for event in diff.patch.iter() {
                tracing::debug!(event_kind = %event.event_kind());

                match &event {
                    AccountEvent::Noop => {
                        tracing::warn!("merge got noop event (server)");
                    }
                    AccountEvent::CreateFolder(id, buf)
                    | AccountEvent::UpdateFolder(id, buf)
                    | AccountEvent::CompactFolder(id, buf)
                    | AccountEvent::ChangeFolderPassword(id, buf) => {
                        self.import_folder(id, buf).await?;
                    }
                    AccountEvent::RenameFolder(id, name) => {
                        let id =
                            self.cache.keys().find(|&fid| fid == id).cloned();
                        if let Some(id) = &id {
                            self.rename_folder(id, name).await?;
                        }
                    }
                    AccountEvent::DeleteFolder(id) => {
                        let id =
                            self.cache.keys().find(|&fid| fid == id).cloned();
                        if let Some(id) = &id {
                            self.delete_folder(id).await?;
                        }
                    }
                }
            }
        } else {
            // FIXME: handle conflict situation
            println!("todo! account patch could not be merged");
        }

        Ok(diff.patch.len())
    }

    #[cfg(feature = "device")]
    async fn merge_device(&mut self, diff: &DeviceDiff) -> Result<usize> {
        tracing::debug!(
            before = ?diff.before,
            num_events = diff.patch.len(),
            "device",
        );

        let checked_patch = {
            let mut event_log = self.device_log.write().await;
            event_log.patch_checked(&diff.before, &diff.patch).await?
        };

        if let CheckedPatch::Success(_, _) = &checked_patch {
            let event_log = self.device_log.read().await;
            let reducer = DeviceReducer::new(&*event_log);
            self.devices = reducer.reduce().await?;
        } else {
            // FIXME: handle conflict situation
            println!("todo! device patch could not be merged");
        }

        Ok(diff.patch.len())
    }

    async fn merge_folders(
        &mut self,
        folders: &IndexMap<VaultId, FolderDiff>,
    ) -> Result<usize> {
        let mut num_changes = 0;
        for (id, diff) in folders {
            tracing::debug!(
                folder_id = %id,
                before = ?diff.before,
                num_events = diff.patch.len(),
                "folder",
            );

            let log = self
                .cache
                .get_mut(id)
                .ok_or_else(|| Error::CacheNotAvailable(*id))?;
            let mut log = log.write().await;

            log.patch_checked(&diff.before, &diff.patch).await?;
            num_changes += diff.patch.len();
        }
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

        #[cfg(feature = "device")]
        let device = {
            let reader = self.device_log.read().await;
            reader.tree().commit_state()?
        };

        #[cfg(feature = "files")]
        let files = {
            let reader = self.file_log.read().await;
            if reader.tree().is_empty() {
                None
            } else {
                Some(reader.tree().commit_state()?)
            }
        };

        let mut folders = IndexMap::new();
        for (id, event_log) in &self.cache {
            let event_log = event_log.read().await;
            let commit_state = event_log.tree().commit_state()?;
            folders.insert(*id, commit_state);
        }
        Ok(SyncStatus {
            identity,
            account,
            #[cfg(feature = "device")]
            device,
            #[cfg(feature = "files")]
            files,
            folders,
        })
    }

    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        Ok(Arc::clone(&self.identity_log))
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        Ok(Arc::clone(&self.account_log))
    }

    #[cfg(feature = "device")]
    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        Ok(Arc::clone(&self.device_log))
    }

    #[cfg(feature = "files")]
    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        Ok(Arc::clone(&self.file_log))
    }

    async fn folder_identifiers(&self) -> Result<Vec<VaultId>> {
        Ok(self.cache.keys().copied().collect())
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        Ok(Arc::clone(
            self.cache.get(id).ok_or(Error::CacheNotAvailable(*id))?,
        ))
    }
}
