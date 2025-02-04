//! Synchronization helpers.
use crate::{filesystem::ServerFileStorage, ServerAccountStorage};
use crate::{Error, Result};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::{
    AccountEventLog, DeviceEventLog, FileEventLog, FolderEventLog,
    VaultWriter,
};
use sos_core::{
    encode,
    events::{
        patch::{
            AccountDiff, CheckedPatch, DeviceDiff, FileDiff, FolderDiff,
        },
        AccountEvent, EventLog, LogEvent, WriteEvent,
    },
    VaultId,
};
use sos_reducers::{DeviceReducer, FolderReducer};
use sos_sync::{
    ForceMerge, Merge, MergeOutcome, StorageEventLogs, SyncStorage,
    TrackedChanges,
};
use sos_vault::{EncryptedEntry, Header, Summary};
use sos_vfs as vfs;
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
        event_log.replace_all_events(&diff).await?;

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

    async fn force_merge_device(
        &mut self,
        diff: DeviceDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<()> {
        <ServerFileStorage as ForceMerge>::force_merge_device(
            self, diff, outcome,
        )
        .await?;

        // Update in-memory cache of trusted devices
        let event_log = self.device_log().await?;
        let event_log = event_log.read().await;
        let reducer = DeviceReducer::new(&*event_log);
        let devices = reducer.reduce().await?;
        self.devices = devices;

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

        let mut event_log =
            FolderEventLog::new_fs_folder(events_path).await?;
        event_log.replace_all_events(&diff).await?;

        let vault = FolderReducer::new()
            .reduce(&event_log)
            .await?
            .build(false)
            .await?;

        let buffer = encode(&vault).await?;
        vfs::write(vault_path, buffer).await?;

        self.folders
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
                        let mut file = VaultWriter::new_fs(path);
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
                        let id = self
                            .folders
                            .keys()
                            .find(|&fid| fid == id)
                            .cloned();
                        if let Some(id) = &id {
                            self.rename_folder(id, name).await?;
                        }
                    }
                    AccountEvent::DeleteFolder(id) => {
                        let id = self
                            .folders
                            .keys()
                            .find(|&fid| fid == id)
                            .cloned();
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

        let log = self.folders.get_mut(folder_id).ok_or_else(|| {
            sos_backend::StorageError::CacheNotAvailable(*folder_id)
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
                    let mut writer = VaultWriter::new_fs(path);
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
}

#[async_trait]
impl StorageEventLogs for ServerFileStorage {
    type Error = Error;

    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        Ok(self.identity_log.clone())
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        Ok(self.account_log.clone())
    }

    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        Ok(self.device_log.clone())
    }

    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        Ok(self.file_log.clone())
    }

    async fn folder_details(&self) -> Result<IndexSet<Summary>> {
        let ids = self.folders.keys().copied().collect::<Vec<_>>();
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
        Ok(Arc::clone(self.folders.get(id).ok_or(
            sos_backend::StorageError::CacheNotAvailable(*id),
        )?))
    }
}

#[async_trait]
impl SyncStorage for ServerFileStorage {
    fn is_client_storage(&self) -> bool {
        false
    }
}
