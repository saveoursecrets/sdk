//! Synchronization helpers.
use crate::{
    commit::{CommitState, Comparison},
    encode,
    events::{
        AccountEvent, AccountEventLog, EventLogExt, FolderEventLog,
        FolderReducer, LogEvent, WriteEvent,
    },
    storage::ServerStorage,
    sync::{
        AccountDiff, ChangeSet, CheckedPatch, FolderDiff, FolderPatch,
        MaybeDiff, Merge, SyncStatus, SyncStorage, UpdateSet,
    },
    vault::VaultId,
    vfs, Error, Paths, Result,
};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::sync::Arc;
use tokio::sync::RwLock;

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

        let vault = FolderReducer::new()
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

        #[cfg(feature = "files")]
        {
            let mut writer = self.file_log.write().await;
            writer.patch_unchecked(&account_data.files).await?;
        }

        for (id, folder) in &account_data.folders {
            let vault_path = self.paths.vault_path(id);
            let events_path = self.paths.event_log_path(id);

            let mut event_log = FolderEventLog::new(events_path).await?;
            event_log.patch_unchecked(folder).await?;

            let vault = FolderReducer::new()
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

    /// Update an account from a change set of event logs and
    /// event diffs.
    ///
    /// Overwrites all existing account data with the event logs
    /// in the change set.
    ///
    /// Intended to be used to perform a destructive overwrite
    /// when changing the encryption cipher or other events
    /// which rewrite the account data.
    pub async fn update_account(
        &mut self,
        mut account_data: UpdateSet,
    ) -> Result<()> {
        // Force overwrite all identity data
        if let Some(identity) = account_data.identity.take() {
            let mut writer = self.identity_log.write().await;
            writer.clear().await?;
            writer.apply(identity.iter().collect()).await?;

            // Rebuild the head-only identity vault
            let vault = FolderReducer::new()
                .reduce(&writer)
                .await?
                .build(false)
                .await?;

            let buffer = encode(&vault).await?;
            vfs::write(self.paths.identity_vault(), buffer).await?;
        }

        // Force overwrite account folders
        for (id, folder) in &account_data.folders {
            let vault_path = self.paths.vault_path(id);
            let events_path = self.paths.event_log_path(id);

            let mut event_log = FolderEventLog::new(events_path).await?;
            event_log.clear().await?;
            event_log.apply(folder.iter().collect()).await?;

            let vault = FolderReducer::new()
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
}

#[async_trait]
impl Merge for ServerStorage {
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

    async fn compare_identity(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let reader = self.identity_log.read().await;
        reader.tree().compare(&state.1)
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

    async fn compare_account(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let reader = self.account_log.read().await;
        reader.tree().compare(&state.1)
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

    #[cfg(feature = "device")]
    async fn compare_device(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let reader = self.device_log.read().await;
        reader.tree().compare(&state.1)
    }

    #[cfg(feature = "files")]
    async fn merge_files(&mut self, diff: &FileDiff) -> Result<usize> {
        tracing::debug!(
            before = ?diff.before,
            num_events = diff.patch.len(),
            "files",
        );

        let num_events = diff.patch.len();
        let mut event_log = self.file_log.write().await;

        // File events may not have a root commit if there are
        // no files yet and we distinguish this by the before
        // commit state being the default.
        let is_init_diff = diff.before == Default::default();
        let checked_patch = if is_init_diff && event_log.tree().is_empty() {
            event_log.apply((&diff.patch).into()).await?;
            None
        } else {
            Some(event_log.patch_checked(&diff.before, &diff.patch).await?)
        };

        let num_changes = if let Some(checked_patch) = checked_patch {
            if let CheckedPatch::Success(_, _) = &checked_patch {
                num_events
            } else {
                0
            }
        } else {
            num_events
        };

        Ok(num_changes)
    }

    #[cfg(feature = "files")]
    async fn compare_files(&self, state: &CommitState) -> Result<Comparison> {
        let reader = self.file_log.read().await;
        reader.tree().compare(&state.1)
    }

    async fn merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: &FolderDiff,
    ) -> Result<usize> {
        tracing::debug!(
            folder_id = %folder_id,
            before = ?diff.before,
            num_events = diff.patch.len(),
            "folder",
        );

        let log = self
            .cache
            .get_mut(folder_id)
            .ok_or_else(|| Error::CacheNotAvailable(*folder_id))?;
        let mut log = log.write().await;

        log.patch_checked(&diff.before, &diff.patch).await?;

        Ok(diff.patch.len())
    }

    async fn compare_folder(
        &self,
        folder_id: &VaultId,
        state: &CommitState,
    ) -> Result<Comparison> {
        let log = self
            .cache
            .get(folder_id)
            .ok_or_else(|| Error::CacheNotAvailable(*folder_id))?;
        let log = log.read().await;
        Ok(log.tree().compare(&state.1)?)
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
