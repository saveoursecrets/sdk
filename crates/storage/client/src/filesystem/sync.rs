use super::ClientFileSystemStorage;
use crate::{
    folder_sync::{FolderMerge, FolderMergeOptions, IdentityFolderMerge},
    ClientAccountStorage, ClientFolderStorage, Error, Result,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::{
    AccountEventLog, DeviceEventLog, FolderEventLog, StorageError,
};
use sos_core::{
    decode,
    events::{
        patch::{AccountDiff, CheckedPatch, DeviceDiff, FolderDiff},
        AccountEvent, EventLog, LogEvent, WriteEvent,
    },
    VaultId,
};
use sos_reducers::DeviceReducer;
use sos_sync::{
    ForceMerge, Merge, MergeOutcome, StorageEventLogs, SyncStorage,
    TrackedChanges,
};
use sos_vault::{Summary, Vault};
use std::{collections::HashSet, sync::Arc};
use tokio::sync::RwLock;

#[cfg(feature = "files")]
use {sos_backend::FileEventLog, sos_core::events::patch::FileDiff};

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StorageEventLogs for ClientFileSystemStorage {
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

    #[cfg(feature = "files")]
    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        Ok(self.file_log.clone())
    }

    async fn folder_details(&self) -> Result<IndexSet<Summary>> {
        let folders = self.list_folders();
        Ok(folders.into_iter().cloned().collect())
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        let folder = self
            .folders
            .get(id)
            .ok_or(StorageError::CacheNotAvailable(*id))?;
        Ok(folder.event_log())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ForceMerge for ClientFileSystemStorage {
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

        self.authenticated_user_mut()?
            .identity_mut()?
            .force_merge(&diff)
            .await?;
        outcome.changes += len;
        outcome.tracked.identity =
            TrackedChanges::new_folder_records(&diff.patch).await?;
        Ok(())
    }

    /// Force merge changes to the files event log.
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

        let folder = self
            .folders
            .get_mut(folder_id)
            .ok_or_else(|| StorageError::CacheNotAvailable(*folder_id))?;
        folder.force_merge(&diff).await?;

        outcome.changes += len;
        outcome.tracked.add_tracked_folder_changes(
            folder_id,
            TrackedChanges::new_folder_records(&diff.patch).await?,
        );

        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Merge for ClientFileSystemStorage {
    async fn merge_identity(
        &mut self,
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        let len = diff.patch.len() as u64;

        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = len,
            "identity",
        );

        let (checked_patch, _) = self
            .authenticated_user_mut()?
            .identity_mut()?
            .merge(&diff)
            .await?;

        if let CheckedPatch::Success(_) = &checked_patch {
            outcome.changes += len;
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
                let time = record.time();
                let event = record.decode_event::<AccountEvent>().await?;
                tracing::debug!(
                    time = %time,
                    event_kind = %event.event_kind(),
                );

                match &event {
                    AccountEvent::Noop => {
                        tracing::warn!("merge got noop event (client)");
                    }
                    AccountEvent::RenameAccount(name) => {
                        self.authenticated_user_mut()?
                            .rename_account(name.to_owned())
                            .await?;
                    }
                    AccountEvent::UpdateIdentity(buf) => {
                        let vault: Vault = decode(buf).await?;
                        self.import_identity_vault(vault).await?;
                    }
                    AccountEvent::CreateFolder(id, buf)
                    | AccountEvent::UpdateFolder(id, buf)
                    | AccountEvent::CompactFolder(id, buf)
                    | AccountEvent::ChangeFolderPassword(id, buf) => {
                        // If the folder was created and later deleted
                        // in the same sequence of events then the folder
                        // password won't exist after merging the identity
                        // events so we need to skip the operation.
                        if let Ok(Some(key)) = self
                            .authenticated_user()?
                            .identity()?
                            .find_folder_password(id)
                            .await
                        {
                            // Must operate on the storage level otherwise
                            // we would duplicate identity events for folder
                            // password
                            self.import_folder(
                                buf,
                                Some(&key),
                                false,
                                Some(time),
                            )
                            .await?;
                        }
                    }
                    AccountEvent::RenameFolder(id, name) => {
                        let summary = self.find(|s| s.id() == id).cloned();
                        if let Some(summary) = &summary {
                            // Note that this event is recorded at both
                            // the account level and the folder level so
                            // we only update the in-memory version here
                            // and let the folder merge make the other
                            // necessary changes
                            self.set_folder_name(summary, name)?;
                        }
                    }
                    AccountEvent::DeleteFolder(id) => {
                        let summary = self.find(|s| s.id() == id).cloned();
                        if let Some(summary) = &summary {
                            self.delete_folder(summary, false).await?;
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
            let devices = {
                let event_log = self.device_log.read().await;
                let reducer = DeviceReducer::new(&*event_log);
                reducer.reduce().await?
            };

            self.devices = devices;

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
        use sos_reducers::FileReducer;
        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = diff.patch.len(),
            "files",
        );

        let mut event_log = self.file_log.write().await;

        // File events may not have a root commit
        let is_init_diff = diff.last_commit.is_none();
        let (checked_patch, external_files) =
            if is_init_diff && event_log.tree().is_empty() {
                event_log.patch_unchecked(&diff.patch).await?;
                let reducer = FileReducer::new(&*event_log);
                let external_files = reducer.reduce(None).await?;

                let proof = event_log.tree().head()?;
                (CheckedPatch::Success(proof), external_files)
            } else {
                let checked_patch = event_log
                    .patch_checked(&diff.checkpoint, &diff.patch)
                    .await?;
                let reducer = FileReducer::new(&*event_log);
                let external_files =
                    reducer.reduce(diff.last_commit.as_ref()).await?;
                (checked_patch, external_files)
            };

        outcome.external_files = external_files;

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

        let (checked_patch, events) = {
            #[cfg(feature = "search")]
            let search = {
                let index = self.index()?;
                index.search()
            };

            tracing::debug!(
                folder_id = %folder_id,
                checkpoint = ?diff.checkpoint,
                num_events = len,
                "folder",
            );

            let folder = self
                .folders
                .get_mut(folder_id)
                .ok_or_else(|| StorageError::CacheNotAvailable(*folder_id))?;

            #[cfg(feature = "search")]
            {
                let mut search = search.write().await;
                folder
                    .merge(
                        &diff,
                        FolderMergeOptions::Search(*folder_id, &mut search),
                    )
                    .await?
            }

            #[cfg(not(feature = "search"))]
            {
                folder
                    .merge(
                        &diff,
                        FolderMergeOptions::Urn(
                            *folder_id,
                            &mut Default::default(),
                        ),
                    )
                    .await?
            }
        };

        if let CheckedPatch::Success(_) = &checked_patch {
            let flags_changed = events
                .iter()
                .find(|e| matches!(e, WriteEvent::SetVaultFlags(_)))
                .is_some();

            // If the flags changed ensure the in-memory summaries
            // are up to date
            if flags_changed {
                self.load_folders().await?;
            }

            outcome.changes += len;
            outcome.tracked.add_tracked_folder_changes(
                folder_id,
                TrackedChanges::new_folder_records(&diff.patch).await?,
            );
        }

        Ok((checked_patch, events))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SyncStorage for ClientFileSystemStorage {
    fn is_client_storage(&self) -> bool {
        true
    }
}
