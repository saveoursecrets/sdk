//! Synchronization helpers.
use super::ServerStorage;
use crate::{
    protocol::sync::{
        CreateSet, ForceMerge, Merge, MergeOutcome, SyncStatus, SyncStorage,
        UpdateSet,
    },
    sdk::{
        commit::{CommitState, CommitTree, Comparison},
        encode,
        events::{
            AccountDiff, AccountEvent, AccountEventLog, CheckedPatch,
            EventLogExt, FolderDiff, FolderEventLog, FolderPatch,
            FolderReducer, LogEvent,
        },
        storage::StorageEventLogs,
        vault::{VaultAccess, VaultId, VaultWriter},
        vfs, Error, Paths, Result,
    },
};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(feature = "device")]
use crate::sdk::events::{DeviceDiff, DeviceEventLog, DeviceReducer};

#[cfg(feature = "files")]
use crate::sdk::events::{FileDiff, FileEventLog};

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
        // let events: Vec<&WriteEvent> = identity_patch.into();

        let mut event_log =
            FolderEventLog::new(paths.identity_events()).await?;
        event_log.clear().await?;
        event_log.patch_unchecked(identity_patch).await?;

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
        account_data: &CreateSet,
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
        mut update_set: UpdateSet,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        if let Some(diff) = update_set.identity.take() {
            self.force_merge_identity(diff, outcome).await?;
        }

        if let Some(diff) = update_set.account.take() {
            self.force_merge_account(diff, outcome).await?;
        }

        #[cfg(feature = "device")]
        if let Some(diff) = update_set.device.take() {
            self.force_merge_device(diff, outcome).await?;
        }

        #[cfg(feature = "files")]
        if let Some(diff) = update_set.files.take() {
            self.force_merge_files(diff, outcome).await?;
        }

        for (id, folder) in update_set.folders {
            self.force_merge_folder(&id, folder, outcome).await?;
        }

        Ok(())
    }
}

#[async_trait]
impl ForceMerge for ServerStorage {
    async fn force_merge_identity(
        &mut self,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        let len = diff.patch.len() as u64;

        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = len,
            "force_merge::identity",
        );

        let mut event_log = self.identity_log.write().await;
        event_log.patch_replace(diff).await?;

        // Rebuild the head-only identity vault
        let vault = FolderReducer::new()
            .reduce(&*event_log)
            .await?
            .build(false)
            .await?;

        let buffer = encode(&vault).await?;
        vfs::write(self.paths.identity_vault(), buffer).await?;

        outcome.identity = len;
        outcome.changes += len;
        Ok(())
    }

    async fn force_merge_account(
        &mut self,
        diff: AccountDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        let len = diff.patch.len() as u64;

        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = len,
            "force_merge::account",
        );

        let event_log = self.account_log();
        let mut event_log = event_log.write().await;
        event_log.patch_replace(diff).await?;

        outcome.identity = len;
        outcome.changes += len;

        Ok(())
    }

    #[cfg(feature = "device")]
    async fn force_merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        let len = diff.patch.len() as u64;

        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = len,
            "force_merge::device",
        );

        let event_log = self.device_log().await?;
        let mut event_log = event_log.write().await;
        event_log.patch_replace(diff).await?;

        // Update in-memory cache of trusted devices
        let reducer = DeviceReducer::new(&event_log);
        let devices = reducer.reduce().await?;
        self.devices = devices;

        outcome.identity = len;
        outcome.changes += len;

        Ok(())
    }

    /// Force merge changes to the files event log.
    #[cfg(feature = "files")]
    async fn force_merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        let len = diff.patch.len() as u64;

        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = len,
            "force_merge::files",
        );

        let event_log = self.file_log().await?;
        let mut event_log = event_log.write().await;
        event_log.patch_replace(diff).await?;

        outcome.identity = len;
        outcome.changes += len;

        Ok(())
    }

    async fn force_merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        let len = diff.patch.len() as u64;

        tracing::debug!(
            folder_id = %folder_id,
            checkpoint = ?diff.checkpoint,
            num_events = len,
            "force_merge::folder",
        );

        let vault_path = self.paths.vault_path(folder_id);
        let events_path = self.paths.event_log_path(folder_id);

        let mut event_log = FolderEventLog::new(events_path).await?;
        event_log.patch_replace(diff).await?;

        let vault = FolderReducer::new()
            .reduce(&event_log)
            .await?
            .build(false)
            .await?;

        let buffer = encode(&vault).await?;
        vfs::write(vault_path, buffer).await?;

        self.cache_mut()
            .insert(*folder_id, Arc::new(RwLock::new(event_log)));

        outcome.folders.insert(*folder_id, len);
        outcome.changes += len;

        Ok(())
    }
}

#[async_trait]
impl Merge for ServerStorage {
    async fn merge_identity(
        &mut self,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = diff.patch.len(),
            "identity",
        );

        let mut writer = self.identity_log.write().await;
        let checked_patch =
            writer.patch_checked(&diff.checkpoint, &diff.patch).await?;

        if let CheckedPatch::Success(_) = &checked_patch {
            outcome.identity = diff.patch.len() as u64;
            outcome.changes += diff.patch.len() as u64;
        }

        Ok(checked_patch)
    }

    async fn compare_identity(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let reader = self.identity_log.read().await;
        reader.tree().compare(&state.1)
    }

    async fn merge_account(
        &mut self,
        diff: AccountDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = diff.patch.len(),
            "account",
        );

        let checked_patch = {
            let mut event_log = self.account_log.write().await;
            event_log
                .patch_checked(&diff.checkpoint, &diff.patch)
                .await?
        };

        if let CheckedPatch::Success(_) = &checked_patch {
            for record in diff.patch.iter() {
                let event = record.decode_event::<AccountEvent>().await?;
                tracing::debug!(event_kind = %event.event_kind());

                match &event {
                    AccountEvent::Noop => {
                        tracing::warn!("merge got noop event (server)");
                    }
                    AccountEvent::RenameAccount(name) => {
                        let path = self.paths.identity_vault();
                        let vault_file = VaultWriter::open(&path).await?;
                        let mut file = VaultWriter::new(&path, vault_file)?;
                        file.set_vault_name(name.to_owned()).await?;
                    }
                    AccountEvent::UpdateIdentity(_) => {
                        // This event is handled on the server
                        // by a call to update_account() so there
                        // is no need to handle this here
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

            outcome.account = diff.patch.len() as u64;
            outcome.changes += diff.patch.len() as u64;
        } else {
            // FIXME: handle conflict situation
            println!("todo! account patch could not be merged");
        }

        Ok(checked_patch)
    }

    async fn compare_account(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let reader = self.account_log.read().await;
        reader.tree().compare(&state.1)
    }

    #[cfg(feature = "device")]
    async fn merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = diff.patch.len(),
            "device",
        );

        let checked_patch = {
            let mut event_log = self.device_log.write().await;
            event_log
                .patch_checked(&diff.checkpoint, &diff.patch)
                .await?
        };

        if let CheckedPatch::Success(_) = &checked_patch {
            // Update in-memory cache of trusted devices
            let event_log = self.device_log.read().await;
            let reducer = DeviceReducer::new(&*event_log);
            self.devices = reducer.reduce().await?;

            outcome.device = diff.patch.len() as u64;
            outcome.changes += diff.patch.len() as u64;
        } else {
            // FIXME: handle conflict situation
            println!("todo! device patch could not be merged");
        }

        Ok(checked_patch)
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
    async fn merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = diff.patch.len(),
            "files",
        );

        let mut event_log = self.file_log.write().await;

        // File events may not have a root commit if there are
        // no files yet and we distinguish this by the before
        // commit state being the default.
        let is_init_diff = diff.checkpoint == Default::default();
        let checked_patch = if is_init_diff && event_log.tree().is_empty() {
            event_log.patch_unchecked(&diff.patch).await?;
            let proof = event_log.tree().head()?;
            CheckedPatch::Success(proof)
        } else {
            event_log
                .patch_checked(&diff.checkpoint, &diff.patch)
                .await?
        };

        if let CheckedPatch::Success(_) = &checked_patch {
            outcome.files = diff.patch.len() as u64;
            outcome.changes += diff.patch.len() as u64;
        }

        Ok(checked_patch)
    }

    #[cfg(feature = "files")]
    async fn compare_files(&self, state: &CommitState) -> Result<Comparison> {
        let reader = self.file_log.read().await;
        reader.tree().compare(&state.1)
    }

    async fn merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        let len = diff.patch.len() as u64;

        tracing::debug!(
            folder_id = %folder_id,
            checkpoint = ?diff.checkpoint,
            num_events = len,
            "folder",
        );

        let log = self
            .cache
            .get_mut(folder_id)
            .ok_or_else(|| Error::CacheNotAvailable(*folder_id))?;
        let mut log = log.write().await;

        let checked_patch =
            log.patch_checked(&diff.checkpoint, &diff.patch).await?;

        if let CheckedPatch::Success(_) = &checked_patch {
            outcome.folders.insert(*folder_id, len);
            outcome.changes += len;
        }

        Ok(checked_patch)
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
impl StorageEventLogs for ServerStorage {
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

#[async_trait]
impl SyncStorage for ServerStorage {
    async fn sync_status(&self) -> Result<SyncStatus> {
        // NOTE: the order for computing the cumulative
        // NOTE: root hash must be identical to the logic
        // NOTE: in the client implementation and the folders
        // NOTE: collection must be sorted so that the folders
        // NOTE: root hash is deterministic

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
        let mut folder_roots: Vec<(&VaultId, [u8; 32])> =
            Vec::with_capacity(self.cache.len());
        for (id, event_log) in &self.cache {
            let event_log = event_log.read().await;
            let commit_state = event_log.tree().commit_state()?;
            folder_roots.push((id, commit_state.1.root().into()));
            folders.insert(*id, commit_state);
        }

        // Compute a root hash of all the trees for an account
        let mut root_tree = CommitTree::new();
        let mut root_commits = vec![
            identity.1.root().into(),
            account.1.root().into(),
            #[cfg(feature = "device")]
            device.1.root().into(),
        ];
        #[cfg(feature = "files")]
        if let Some(files) = &files {
            root_commits.push(files.1.root().into());
        }

        folder_roots.sort_by(|a, b| a.0.cmp(b.0));
        let mut folder_roots =
            folder_roots.into_iter().map(|f| f.1).collect::<Vec<_>>();

        root_commits.append(&mut folder_roots);
        root_tree.append(&mut root_commits);
        root_tree.commit();

        let root = root_tree.root().ok_or(Error::NoRootCommit)?;

        Ok(SyncStatus {
            root,
            identity,
            account,
            #[cfg(feature = "device")]
            device,
            #[cfg(feature = "files")]
            files,
            folders,
        })
    }
}
