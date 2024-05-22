use crate::{
    account::{Account, LocalAccount},
    commit::{CommitState, Comparison},
    decode,
    events::{AccountEvent, EventLogExt, LogEvent},
    storage::StorageEventLogs,
    sync::{
        AccountDiff, CheckedPatch, FolderDiff, FolderMergeOptions, Merge,
        SyncStatus, SyncStorage,
    },
    vault::{Vault, VaultId},
    Error, Result,
};
use async_trait::async_trait;
use indexmap::IndexMap;

#[cfg(feature = "device")]
use crate::{events::DeviceReducer, sync::DeviceDiff};

#[cfg(feature = "files")]
use crate::sync::FileDiff;

#[async_trait]
impl Merge for LocalAccount {
    async fn merge_identity(&mut self, diff: &FolderDiff) -> Result<usize> {
        tracing::debug!(
            before = ?diff.before,
            num_events = diff.patch.len(),
            "identity",
        );
        self.user_mut()?.identity_mut()?.merge(diff).await?;
        Ok(diff.patch.len())
    }

    async fn compare_identity(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let log = self.identity_log().await?;
        let event_log = log.read().await;
        event_log.tree().compare(&state.1)
    }

    async fn merge_account(&mut self, diff: &AccountDiff) -> Result<usize> {
        tracing::debug!(
            before = ?diff.before,
            num_events = diff.patch.len(),
            "account",
        );

        let checked_patch = {
            let account_log = self.account_log().await?;
            let mut event_log = account_log.write().await;
            event_log.patch_checked(&diff.before, &diff.patch).await?
        };

        if let CheckedPatch::Success(_, _) = &checked_patch {
            for event in diff.patch.iter() {
                tracing::debug!(event_kind = %event.event_kind());

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
                        if let Ok(key) = self
                            .user()?
                            .identity()?
                            .find_folder_password(id)
                            .await
                        {
                            // Must operate on the storage level otherwise
                            // we would duplicate identity events for folder
                            // password
                            let storage = self.storage().await?;
                            let mut storage = storage.write().await;
                            storage
                                .import_folder(buf, Some(&key), false)
                                .await?;
                        }
                    }
                    AccountEvent::RenameFolder(id, name) => {
                        let summary = self.find(|s| s.id() == id).await;
                        if let Some(summary) = &summary {
                            let storage = self.storage().await?;
                            let mut storage = storage.write().await;
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
                            let storage = self.storage().await?;
                            let mut storage = storage.write().await;
                            storage.delete_folder(summary, false).await?;
                        }
                    }
                }
            }
        }

        Ok(diff.patch.len())
    }

    async fn compare_account(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let log = self.account_log().await?;
        let event_log = log.read().await;
        event_log.tree().compare(&state.1)
    }

    #[cfg(feature = "device")]
    async fn merge_device(&mut self, diff: &DeviceDiff) -> Result<usize> {
        tracing::debug!(
            before = ?diff.before,
            num_events = diff.patch.len(),
            "device",
        );

        let checked_patch = {
            let storage = self.storage().await?;
            let storage = storage.read().await;
            let mut event_log = storage.device_log.write().await;
            event_log.patch_checked(&diff.before, &diff.patch).await?
        };

        if let CheckedPatch::Success(_, _) = &checked_patch {
            let devices = {
                let storage = self.storage().await?;
                let storage = storage.read().await;
                let event_log = storage.device_log.read().await;
                let reducer = DeviceReducer::new(&*event_log);
                reducer.reduce().await?
            };

            let storage = self.storage().await?;
            let mut storage = storage.write().await;
            storage.devices = devices;
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
        let log = self.device_log().await?;
        let event_log = log.read().await;
        event_log.tree().compare(&state.1)
    }

    #[cfg(feature = "files")]
    async fn merge_files(&mut self, diff: &FileDiff) -> Result<usize> {
        use crate::{
            events::FileReducer, storage::files::TransferOperation, vfs,
        };
        use indexmap::IndexSet;
        use std::collections::HashMap;
        tracing::debug!(
            before = ?diff.before,
            num_events = diff.patch.len(),
            "files",
        );

        let num_events = diff.patch.len();

        let storage = self.storage().await?;
        let storage = storage.read().await;
        let mut event_log = storage.file_log.write().await;

        // File events may not have a root commit
        let is_init_diff = diff.last_commit.is_none();
        let (checked_patch, mut external_files) = if is_init_diff
            && event_log.tree().is_empty()
        {
            event_log.apply((&diff.patch).into()).await?;
            let reducer = FileReducer::new(&event_log);
            let external_files = reducer.reduce(None).await?;
            (None, external_files)
        } else {
            let checked_patch =
                event_log.patch_checked(&diff.before, &diff.patch).await?;
            let reducer = FileReducer::new(&event_log);
            let external_files =
                reducer.reduce(diff.last_commit.as_ref()).await?;
            (Some(checked_patch), external_files)
        };

        // Compute which external files need to be downloaded
        // and add to the transfers queue
        if !external_files.is_empty() {
            let transfers = storage.transfers();
            let mut writer = transfers.write().await;

            for file in external_files.drain(..) {
                let file_path = self.paths().file_location(
                    file.vault_id(),
                    file.secret_id(),
                    file.file_name().to_string(),
                );
                if !vfs::try_exists(file_path).await? {
                    tracing::debug!(
                        file = ?file,
                        "add file download to transfers",
                    );
                    let mut map = HashMap::new();
                    let mut set = IndexSet::new();
                    set.insert(TransferOperation::Download);
                    map.insert(file, set);
                    writer.queue_transfers(map).await?;
                }
            }
        }

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
        let log = self.file_log().await?;
        let event_log = log.read().await;
        event_log.tree().compare(&state.1)
    }

    async fn merge_folder(
        &mut self,
        folder_id: &VaultId,
        diff: &FolderDiff,
    ) -> Result<usize> {
        let mut num_changes = 0;

        let storage = self.storage().await?;
        let mut storage = storage.write().await;

        #[cfg(feature = "search")]
        let search = {
            let index = storage.index.as_ref().ok_or(Error::NoSearchIndex)?;
            index.search()
        };

        tracing::debug!(
            folder_id = %folder_id,
            before = ?diff.before,
            num_events = diff.patch.len(),
            "folder",
        );

        if let Some(folder) = storage.cache_mut().get_mut(folder_id) {
            #[cfg(feature = "search")]
            {
                let mut search = search.write().await;
                folder
                    .merge(
                        diff,
                        FolderMergeOptions::Search(*folder_id, &mut search),
                    )
                    .await?;
            }

            #[cfg(not(feature = "search"))]
            folder.merge(diff, Default::default()).await?;

            num_changes = diff.patch.len();
        }

        Ok(num_changes)
    }

    async fn compare_folder(
        &self,
        folder_id: &VaultId,
        state: &CommitState,
    ) -> Result<Comparison> {
        let storage = self.storage().await?;
        let storage = storage.read().await;

        let folder = storage
            .cache()
            .get(folder_id)
            .ok_or_else(|| Error::CacheNotAvailable(*folder_id))?;
        let event_log = folder.event_log();
        let reader = event_log.read().await;
        Ok(reader.tree().compare(&state.1)?)
    }
}

#[async_trait]
impl SyncStorage for LocalAccount {
    async fn sync_status(&self) -> Result<SyncStatus> {
        let storage = self.storage().await?;
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

        #[cfg(feature = "device")]
        let device = {
            let reader = storage.device_log.read().await;
            reader.tree().commit_state()?
        };

        #[cfg(feature = "files")]
        let files = {
            let reader = storage.file_log.read().await;
            if reader.tree().is_empty() {
                None
            } else {
                Some(reader.tree().commit_state()?)
            }
        };

        let mut folders = IndexMap::new();
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
            #[cfg(feature = "device")]
            device,
            #[cfg(feature = "files")]
            files,
            folders,
        })
    }
}
