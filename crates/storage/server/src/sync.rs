use crate::ServerAccountStorage;
use crate::{Error, Result};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::{AccountEventLog, DeviceEventLog, FolderEventLog};
use sos_core::{
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
use sos_vault::Summary;
use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
    sync::Arc,
};
use tokio::sync::RwLock;

#[cfg(feature = "files")]
use sos_backend::FileEventLog;

// Must use a new type due to the orphan rule.
#[doc(hidden)]
pub struct SyncImpl<T>(T);

impl<T> SyncImpl<T> {
    pub fn new(value: T) -> Self {
        SyncImpl(value)
    }
}

impl<T> Deref for SyncImpl<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for SyncImpl<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[async_trait]
impl<T> StorageEventLogs for SyncImpl<T>
where
    T: StorageEventLogs<Error = Error>,
{
    type Error = Error;

    async fn identity_log(
        &self,
    ) -> std::result::Result<
        Arc<RwLock<FolderEventLog>>,
        <T as StorageEventLogs>::Error,
    > {
        self.0.identity_log().await
    }

    async fn account_log(
        &self,
    ) -> std::result::Result<
        Arc<RwLock<AccountEventLog>>,
        <T as StorageEventLogs>::Error,
    > {
        self.0.account_log().await
    }

    async fn device_log(
        &self,
    ) -> std::result::Result<
        Arc<RwLock<DeviceEventLog>>,
        <T as StorageEventLogs>::Error,
    > {
        self.0.device_log().await
    }

    #[cfg(feature = "files")]
    async fn file_log(
        &self,
    ) -> std::result::Result<
        Arc<RwLock<FileEventLog>>,
        <T as StorageEventLogs>::Error,
    > {
        self.0.file_log().await
    }

    async fn folder_details(
        &self,
    ) -> std::result::Result<IndexSet<Summary>, <T as StorageEventLogs>::Error>
    {
        self.0.folder_details().await
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> std::result::Result<
        Arc<RwLock<FolderEventLog>>,
        <T as StorageEventLogs>::Error,
    > {
        self.0.folder_log(id).await
    }
}

#[async_trait]
impl<T> ForceMerge for SyncImpl<T>
where
    T: StorageEventLogs<Error = Error> + ServerAccountStorage,
{
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

        let identity_log = self.identity_log().await?;
        let mut event_log = identity_log.write().await;
        event_log.replace_all_events(&diff).await?;

        // Rebuild the head-only identity vault
        let vault = FolderReducer::new()
            .reduce(&*event_log)
            .await?
            .build(false)
            .await?;

        self.write_vault(&vault).await?;

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
        let len = diff.patch.len() as u64;

        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = len,
            "force_merge::device",
        );

        let event_log = self.device_log().await?;
        let mut event_log = event_log.write().await;
        event_log.replace_all_events(&diff).await?;

        // Update in-memory cache of trusted devices
        let reducer = DeviceReducer::new(&*event_log);
        let devices = reducer.reduce().await?;
        self.set_devices(devices);

        outcome.changes += len;
        outcome.tracked.device =
            TrackedChanges::new_device_records(&diff.patch).await?;

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

        let (event_log, vault) =
            self.replace_folder(folder_id, &diff).await?;
        self.write_vault(&vault).await?;

        self.folders_mut()
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
impl<T> Merge for SyncImpl<T>
where
    T: StorageEventLogs<Error = Error> + ServerAccountStorage,
{
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

        let identity_log = self.identity_log().await?;
        let mut writer = identity_log.write().await;
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
            let account_log = self.account_log().await?;
            let mut event_log = account_log.write().await;
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
                        self.rename_account(name).await?;
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
                            .folders()
                            .keys()
                            .find(|&fid| fid == id)
                            .cloned();
                        if let Some(id) = &id {
                            self.rename_folder(id, name).await?;
                        }
                    }
                    AccountEvent::DeleteFolder(id) => {
                        let id = self
                            .folders()
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
            let device_log = self.device_log().await?;
            let mut event_log = device_log.write().await;
            event_log
                .patch_checked(&diff.checkpoint, &diff.patch)
                .await?
        };

        if let CheckedPatch::Success(_) = &checked_patch {
            // Update in-memory cache of trusted devices
            let device_log = self.device_log().await?;
            let event_log = device_log.read().await;
            let reducer = DeviceReducer::new(&*event_log);
            self.set_devices(reducer.reduce().await?);

            outcome.changes += diff.patch.len() as u64;
            outcome.tracked.device =
                TrackedChanges::new_device_records(&diff.patch).await?;
        }

        Ok(checked_patch)
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

        let file_log = self.file_log().await?;
        let mut event_log = file_log.write().await;

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

        let checked_patch = {
            let log =
                self.folders_mut().get_mut(folder_id).ok_or_else(|| {
                    sos_backend::StorageError::FolderNotFound(*folder_id)
                })?;
            let mut log = log.write().await;
            log.patch_checked(&diff.checkpoint, &diff.patch).await?
        };

        if let CheckedPatch::Success(_) = &checked_patch {
            // Must update files on disc when we encounter a change
            // to the vault flags so that the NO_SYNC flag will be
            // respected
            let events = diff.patch.into_events::<WriteEvent>().await?;
            for event in events {
                if let WriteEvent::SetVaultFlags(flags) = event {
                    self.set_folder_flags(folder_id, flags).await?;
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
impl<T> SyncStorage for SyncImpl<T>
where
    T: StorageEventLogs<Error = Error> + ServerAccountStorage,
{
    fn is_client_storage(&self) -> bool {
        false
    }
}
