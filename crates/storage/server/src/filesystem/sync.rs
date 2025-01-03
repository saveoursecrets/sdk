//! Synchronization helpers.
use crate::{filesystem::ServerFileStorage, ServerAccountStorage};
use crate::{Error, Result};
use async_trait::async_trait;
use indexmap::{IndexMap, IndexSet};
use sos_core::events::LogEvent;
use sos_core::{
    commit::{CommitState, CommitTree, Comparison},
    VaultId,
};
use sos_sdk::{
    encode,
    events::{
        AccountDiff, AccountEvent, AccountEventLog, CheckedPatch, DeviceDiff,
        DeviceEventLog, DeviceReducer, EventLogExt, FileDiff, FileEventLog,
        FolderDiff, FolderEventLog, WriteEvent,
    },
    vault::{FolderReducer, Header, Summary, VaultAccess, VaultWriter},
    vfs,
};
use sos_sync::{
    ForceMerge, Merge, MergeOutcome, StorageEventLogs, SyncStatus,
    SyncStorage, TrackedChanges,
};
use std::{collections::HashSet, sync::Arc};
use tokio::sync::RwLock;

#[async_trait]
impl ForceMerge for ServerFileStorage {
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
        event_log.patch_replace(&diff).await?;

        // Rebuild the head-only identity vault
        let vault = FolderReducer::new()
            .reduce(&*event_log)
            .await?
            .build(false)
            .await?;

        let buffer = encode(&vault).await?;
        vfs::write(self.paths.identity_vault(), buffer).await?;

        outcome.changes += len;
        outcome.tracked.identity =
            TrackedChanges::new_folder_records(&diff.patch).await?;

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

        let mut event_log = self.account_log.write().await;
        event_log.patch_replace(&diff).await?;

        outcome.changes += len;
        outcome.tracked.account =
            TrackedChanges::new_account_records(&diff.patch).await?;

        Ok(())
    }

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
        event_log.patch_replace(&diff).await?;

        // Update in-memory cache of trusted devices
        let reducer = DeviceReducer::new(&event_log);
        let devices = reducer.reduce().await?;
        self.devices = devices;

        outcome.changes += len;
        outcome.tracked.device =
            TrackedChanges::new_device_records(&diff.patch).await?;

        Ok(())
    }

    /// Force merge changes to the files event log.
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
        event_log.patch_replace(&diff).await?;

        outcome.changes += len;
        outcome.tracked.files =
            TrackedChanges::new_file_records(&diff.patch).await?;

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
        event_log.patch_replace(&diff).await?;

        let vault = FolderReducer::new()
            .reduce(&event_log)
            .await?
            .build(false)
            .await?;

        let buffer = encode(&vault).await?;
        vfs::write(vault_path, buffer).await?;

        self.cache_mut()
            .insert(*folder_id, Arc::new(RwLock::new(event_log)));

        outcome.changes += len;
        outcome.tracked.add_tracked_folder_changes(
            folder_id,
            TrackedChanges::new_folder_records(&diff.patch).await?,
        );

        Ok(())
    }
}

#[async_trait]
impl Merge for ServerFileStorage {
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
            outcome.changes += diff.patch.len() as u64;
            outcome.tracked.identity =
                TrackedChanges::new_folder_records(&diff.patch).await?;
        }

        Ok(checked_patch)
    }

    async fn compare_identity(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let reader = self.identity_log.read().await;
        Ok(reader.tree().compare(&state.1)?)
    }

    async fn merge_account(
        &mut self,
        diff: AccountDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<(CheckedPatch, HashSet<VaultId>)> {
        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = diff.patch.len(),
            "account",
        );

        let mut deleted_folders = HashSet::new();

        let checked_patch = {
            let mut event_log = self.account_log.write().await;
            event_log
                .patch_checked(&diff.checkpoint, &diff.patch)
                .await?
        };

        if let CheckedPatch::Success(_) = &checked_patch {
            let mut events = Vec::new();
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
                            deleted_folders.insert(*id);
                        }
                    }
                }
                events.push(event);
            }

            outcome.changes += diff.patch.len() as u64;
            outcome.tracked.account =
                TrackedChanges::new_account_events(events).await?;
        }

        Ok((checked_patch, deleted_folders))
    }

    async fn compare_account(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let reader = self.account_log.read().await;
        Ok(reader.tree().compare(&state.1)?)
    }

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

            outcome.changes += diff.patch.len() as u64;
            outcome.tracked.device =
                TrackedChanges::new_device_records(&diff.patch).await?;
        }

        Ok(checked_patch)
    }

    async fn compare_device(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let reader = self.device_log.read().await;
        Ok(reader.tree().compare(&state.1)?)
    }

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
            outcome.changes += diff.patch.len() as u64;
            outcome.tracked.files =
                TrackedChanges::new_file_records(&diff.patch).await?;
        }

        Ok(checked_patch)
    }

    async fn compare_files(&self, state: &CommitState) -> Result<Comparison> {
        let reader = self.file_log.read().await;
        Ok(reader.tree().compare(&state.1)?)
    }

    async fn merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<(CheckedPatch, Vec<WriteEvent>)> {
        let len = diff.patch.len() as u64;

        tracing::debug!(
            folder_id = %folder_id,
            checkpoint = ?diff.checkpoint,
            num_events = len,
            "folder",
        );

        let log = self.cache.get_mut(folder_id).ok_or_else(|| {
            sos_database::StorageError::CacheNotAvailable(*folder_id)
        })?;
        let mut log = log.write().await;

        let checked_patch =
            log.patch_checked(&diff.checkpoint, &diff.patch).await?;

        if let CheckedPatch::Success(_) = &checked_patch {
            // Must update files on disc when we encounter a change
            // to the vault flags so that the NO_SYNC flag will be
            // respected
            let events = diff.patch.into_events::<WriteEvent>().await?;
            for event in events {
                if let WriteEvent::SetVaultFlags(flags) = event {
                    let path = self.paths.vault_path(folder_id);
                    let file = VaultWriter::open(&path).await?;
                    let mut writer = VaultWriter::new(path, file)?;
                    writer.set_vault_flags(flags).await?;
                }
            }

            outcome.changes += len;
            outcome.tracked.add_tracked_folder_changes(
                folder_id,
                TrackedChanges::new_folder_records(&diff.patch).await?,
            );
        }

        Ok((checked_patch, vec![]))
    }

    async fn compare_folder(
        &self,
        folder_id: &VaultId,
        state: &CommitState,
    ) -> Result<Comparison> {
        let log = self.cache.get(folder_id).ok_or_else(|| {
            sos_database::StorageError::CacheNotAvailable(*folder_id)
        })?;
        let log = log.read().await;
        Ok(log.tree().compare(&state.1)?)
    }
}

#[async_trait]
impl StorageEventLogs for ServerFileStorage {
    type Error = Error;

    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        Ok(Arc::clone(&self.identity_log))
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        Ok(Arc::clone(&self.account_log))
    }

    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        Ok(Arc::clone(&self.device_log))
    }

    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        Ok(Arc::clone(&self.file_log))
    }

    async fn folder_details(&self) -> Result<IndexSet<Summary>> {
        let ids = self.cache.keys().copied().collect::<Vec<_>>();
        let mut output = IndexSet::new();
        for id in &ids {
            let path = self.paths.vault_path(id);
            let summary = Header::read_summary_file(path).await?;
            output.insert(summary);
        }
        Ok(output)
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        Ok(Arc::clone(self.cache.get(id).ok_or(
            sos_database::StorageError::CacheNotAvailable(*id),
        )?))
    }
}

#[async_trait]
impl SyncStorage for ServerFileStorage {
    fn is_client_storage(&self) -> bool {
        false
    }

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

        let device = {
            let reader = self.device_log.read().await;
            reader.tree().commit_state()?
        };

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
            device.1.root().into(),
        ];

        if let Some(files) = &files {
            root_commits.push(files.1.root().into());
        }

        folder_roots.sort_by(|a, b| a.0.cmp(b.0));
        let mut folder_roots =
            folder_roots.into_iter().map(|f| f.1).collect::<Vec<_>>();

        root_commits.append(&mut folder_roots);
        root_tree.append(&mut root_commits);
        root_tree.commit();

        let root = root_tree.root().ok_or(sos_core::Error::NoRootCommit)?;

        Ok(SyncStatus {
            root,
            identity,
            account,
            device,
            files,
            folders,
        })
    }
}
