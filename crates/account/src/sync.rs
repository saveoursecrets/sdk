//! Implements merging into a local account.
use super::folder_sync::{
    FolderMerge, FolderMergeOptions, IdentityFolderMerge,
};
use crate::{Account, LocalAccount, Result};
use async_trait::async_trait;
use sos_backend::reducers::DeviceReducer;
use sos_backend::StorageError;
use sos_core::{decode, events::EventLog};
use sos_core::{
    events::{
        patch::{AccountDiff, CheckedPatch, DeviceDiff, FolderDiff},
        AccountEvent, LogEvent, WriteEvent,
    },
    VaultId,
};
use sos_sync::{
    ForceMerge, Merge, MergeOutcome, StorageEventLogs, SyncStorage,
    TrackedChanges,
};
use sos_vault::Vault;
use std::collections::HashSet;

#[cfg(feature = "files")]
use sos_core::events::patch::FileDiff;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ForceMerge for LocalAccount {
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

        self.user_mut()?.identity_mut()?.force_merge(&diff).await?;
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

        let mut storage = self.storage.write().await;

        let folder = storage
            .cache_mut()
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
impl Merge for LocalAccount {
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

        let (checked_patch, _) =
            self.user_mut()?.identity_mut()?.merge(&diff).await?;

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
                        self.user_mut()?
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
                            .user()?
                            .identity()?
                            .find_folder_password(id)
                            .await
                        {
                            // Must operate on the storage level otherwise
                            // we would duplicate identity events for folder
                            // password
                            let mut storage = self.storage.write().await;
                            storage
                                .import_folder(
                                    buf,
                                    Some(&key),
                                    false,
                                    Some(time),
                                )
                                .await?;
                        }
                    }
                    AccountEvent::RenameFolder(id, name) => {
                        let summary = self.find(|s| s.id() == id).await;
                        if let Some(summary) = &summary {
                            let mut storage = self.storage.write().await;
                            // Note that this event is recorded at both
                            // the account level and the folder level so
                            // we only update the in-memory version here
                            // and let the folder merge make the other
                            // necessary changes
                            storage.set_folder_name(summary, name)?;
                        }
                    }
                    AccountEvent::DeleteFolder(id) => {
                        let summary = self.find(|s| s.id() == id).await;
                        if let Some(summary) = &summary {
                            let mut storage = self.storage.write().await;
                            storage.delete_folder(summary, false).await?;
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
            let storage = self.storage.read().await;
            let mut event_log = storage.device_log.write().await;
            event_log
                .patch_checked(&diff.checkpoint, &diff.patch)
                .await?
        };

        if let CheckedPatch::Success(_) = &checked_patch {
            let devices = {
                let storage = self.storage.read().await;
                let event_log = storage.device_log.read().await;
                let reducer = DeviceReducer::new(&*event_log);
                reducer.reduce().await?
            };

            let mut storage = self.storage.write().await;
            storage.devices = devices;

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
        use sos_backend::reducers::FileReducer;
        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = diff.patch.len(),
            "files",
        );

        let storage = self.storage.read().await;
        let mut event_log = storage.file_log.write().await;

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
            let mut storage = self.storage.write().await;

            #[cfg(feature = "search")]
            let search = {
                let index = storage
                    .index
                    .as_ref()
                    .ok_or(sos_client_storage::Error::NoSearchIndex)?;
                index.search()
            };

            tracing::debug!(
                folder_id = %folder_id,
                checkpoint = ?diff.checkpoint,
                num_events = len,
                "folder",
            );

            // Try to promote a pending folder when we receive
            // events for a folder.
            //
            // Relies on the server never including events when
            // the NO_SYNC flag has been set.
            let promoted =
                storage.try_promote_pending_folder(folder_id).await?;
            if promoted {
                let key = self.find_folder_password(folder_id).await?.ok_or(
                    sos_client_storage::Error::NoFolderPassword(*folder_id),
                )?;
                storage.unlock_folder(folder_id, &key).await?;
            }

            let folder = storage
                .cache_mut()
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
impl SyncStorage for LocalAccount {
    fn is_client_storage(&self) -> bool {
        true
    }
}
