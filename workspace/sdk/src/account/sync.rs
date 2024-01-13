use super::account::Account;
use crate::{
    events::{
        AccountEvent, AccountEventLog, EventLogExt, FolderEventLog, LogEvent,
    },
    sync::{
        AccountDiff, CheckedPatch, FolderDiff, FolderMergeOptions, SyncDiff,
        SyncStatus, SyncStorage,
    },
    vault::VaultId,
    Error, Result,
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

impl Account {
    /// Merge a diff into this account.
    pub async fn merge(&mut self, diff: &SyncDiff) -> Result<usize> {
        let span = span!(Level::DEBUG, "merge_client");
        let _enter = span.enter();

        let mut num_changes = 0;

        // Identity must be merged first so delegated
        // folder passwords are available before we merge
        // account level events
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

        #[cfg(feature = "files")]
        if let Some(diff) = &diff.files {
            num_changes += self.merge_files(diff).await?;
        }

        num_changes += self.merge_folders(&diff.folders).await?;

        tracing::debug!(num_changes = %num_changes, "merge complete");

        Ok(num_changes)
    }

    async fn merge_identity(&mut self, diff: &FolderDiff) -> Result<usize> {
        tracing::debug!(
            before = ?diff.before,
            num_events = diff.patch.len(),
            "identity",
        );
        self.user_mut()?.identity_mut()?.merge(diff).await?;
        Ok(diff.patch.len())
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
                            let storage = self.storage()?;
                            let mut storage = storage.write().await;
                            storage
                                .import_folder(buf, Some(&key), false)
                                .await?;
                        }
                    }
                    AccountEvent::RenameFolder(id, name) => {
                        let summary = self.find(|s| s.id() == id).await;
                        if let Some(summary) = &summary {
                            let storage = self.storage()?;
                            let mut storage = storage.write().await;
                            // Note that this event is recorded at both
                            // the account level and the folder level so
                            // we only update the in-memory version here
                            // and let the folder merge make the other
                            // necessary changes
                            storage
                                .set_folder_name(summary, name.to_owned())?;
                        }
                    }
                    AccountEvent::DeleteFolder(id) => {
                        let summary = self.find(|s| s.id() == id).await;
                        if let Some(summary) = &summary {
                            let storage = self.storage()?;
                            let mut storage = storage.write().await;
                            storage.delete_folder(summary, false).await?;
                        }
                    }
                }
            }
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
            let storage = self.storage()?;
            let storage = storage.read().await;
            let mut event_log = storage.device_log.write().await;
            event_log.patch_checked(&diff.before, &diff.patch).await?
        };

        if let CheckedPatch::Success(_, _) = &checked_patch {
            let devices = {
                let storage = self.storage()?;
                let storage = storage.read().await;
                let event_log = storage.device_log.read().await;
                let reducer = DeviceReducer::new(&*event_log);
                reducer.reduce().await?
            };

            let storage = self.storage()?;
            let mut storage = storage.write().await;
            storage.devices = devices;
        } else {
            // FIXME: handle conflict situation
            println!("todo! device patch could not be merged");
        }

        Ok(diff.patch.len())
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

        let storage = self.storage()?;
        let storage = storage.read().await;
        let mut event_log = storage.file_log.write().await;

        // File events may not have a root commit
        let is_init_diff = diff.last_commit.is_none();
        let (checked_patch, mut external_files) = if is_init_diff
            && event_log.tree().is_empty()
        {
            event_log.apply((&diff.patch).into()).await?;
            let reducer = FileReducer::new(&*event_log);
            let external_files = reducer.reduce(None).await?;
            (None, external_files)
        } else {
            let checked_patch =
                event_log.patch_checked(&diff.before, &diff.patch).await?;
            let reducer = FileReducer::new(&*event_log);
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
                let file_path = self.paths.file_location(
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

    async fn merge_folders(
        &mut self,
        folders: &IndexMap<VaultId, FolderDiff>,
    ) -> Result<usize> {
        let mut num_changes = 0;

        let storage = self.storage()?;
        let mut storage = storage.write().await;

        #[cfg(feature = "search")]
        let search = {
            let index = storage.index.as_ref().ok_or(Error::NoSearchIndex)?;
            index.search()
        };

        for (id, diff) in folders {
            tracing::debug!(
                folder_id = %id,
                before = ?diff.before,
                num_events = diff.patch.len(),
                "folder",
            );

            if let Some(folder) = storage.cache_mut().get_mut(id) {
                #[cfg(feature = "search")]
                {
                    let mut search = search.write().await;
                    folder
                        .merge(
                            diff,
                            FolderMergeOptions::Search(*id, &mut search),
                        )
                        .await?;
                }

                #[cfg(not(feature = "search"))]
                folder.merge(diff, Default::default()).await?;

                num_changes += diff.patch.len();
            }
        }

        Ok(num_changes)
    }
}

#[async_trait]
impl SyncStorage for Account {
    async fn sync_status(&self) -> Result<SyncStatus> {
        let storage = self.storage()?;
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

    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>> {
        let storage = self.storage()?;
        let storage = storage.read().await;
        Ok(Arc::clone(&storage.identity_log))
    }

    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>> {
        let storage = self.storage()?;
        let storage = storage.read().await;
        Ok(Arc::clone(&storage.account_log))
    }

    #[cfg(feature = "device")]
    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>> {
        let storage = self.storage()?;
        let storage = storage.read().await;
        Ok(Arc::clone(&storage.device_log))
    }

    #[cfg(feature = "files")]
    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>> {
        let storage = self.storage()?;
        let storage = storage.read().await;
        Ok(Arc::clone(&storage.file_log))
    }

    async fn folder_identifiers(&self) -> Result<Vec<VaultId>> {
        let storage = self.storage()?;
        let storage = storage.read().await;
        let summaries = storage.list_folders().to_vec();
        Ok(summaries.iter().map(|s| *s.id()).collect())
    }

    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>> {
        let storage = self.storage()?;
        let storage = storage.read().await;
        let folder = storage
            .cache()
            .get(id)
            .ok_or(Error::CacheNotAvailable(*id))?;
        Ok(folder.event_log())
    }
}
