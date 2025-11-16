use crate::{
    folder_sync::{FolderMerge, FolderMergeOptions, IdentityFolderMerge},
    traits::private::Internal,
    ClientAccountStorage, ClientDeviceStorage, ClientFolderStorage, Error,
    Result,
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
    AuthenticationError, VaultId,
};
use sos_login::DelegatedAccess;
use sos_reducers::DeviceReducer;
use sos_sync::{
    ForceMerge, Merge, MergeOutcome, StorageEventLogs, SyncStorage,
    TrackedChanges,
};
use sos_vault::{Summary, Vault};
use std::{
    collections::HashSet,
    ops::{Deref, DerefMut},
    sync::Arc,
};
use tokio::sync::RwLock;

#[cfg(feature = "files")]
use {sos_backend::FileEventLog, sos_core::events::patch::FileDiff};

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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<T> ForceMerge for SyncImpl<T>
where
    T: StorageEventLogs<Error = Error>
        + ClientAccountStorage
        + ClientDeviceStorage
        + ClientFolderStorage,
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

        self.0
            .authenticated_user_mut()
            .ok_or(AuthenticationError::NotAuthenticated)?
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
            .0
            .folders_mut()
            .get_mut(folder_id)
            .ok_or_else(|| StorageError::FolderNotFound(*folder_id))?;
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
impl<T> Merge for SyncImpl<T>
where
    T: StorageEventLogs<Error = Error>
        + ClientAccountStorage
        + ClientDeviceStorage
        + ClientFolderStorage,
{
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
            .0
            .authenticated_user_mut()
            .ok_or(AuthenticationError::NotAuthenticated)?
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
                        self.0
                            .authenticated_user_mut()
                            .ok_or(AuthenticationError::NotAuthenticated)?
                            .rename_account(name.to_owned())
                            .await?;
                    }
                    AccountEvent::UpdateIdentity(buf) => {
                        let vault: Vault = decode(buf).await?;
                        self.0.import_login_vault(vault).await?;
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
                            .0
                            .authenticated_user()
                            .ok_or(AuthenticationError::NotAuthenticated)?
                            .identity()?
                            .find_folder_password(id)
                            .await
                        {
                            // Must operate on the storage level otherwise
                            // we would duplicate identity events for folder
                            // password
                            self.0
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
                        // Note that this event is recorded at both
                        // the account level and the folder level so
                        // we only update the in-memory version here
                        // and let the folder merge make the other
                        // necessary changes
                        self.0.set_folder_name(id, name, Internal)?;
                    }
                    AccountEvent::DeleteFolder(id) => {
                        if self.0.find(|f| f.id() == id).is_some() {
                            self.0.delete_folder(id, false).await?;
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
            let devices = {
                let device_log = self.device_log().await?;
                let event_log = device_log.read().await;
                let reducer = DeviceReducer::new(&*event_log);
                reducer.reduce().await?
            };

            self.0.set_devices(devices, Internal);

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

        let file_log = self.file_log().await?;
        let mut event_log = file_log.write().await;

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
                let index = self
                    .0
                    .search_index()
                    .ok_or_else(|| AuthenticationError::NotAuthenticated)?;
                index.search()
            };

            tracing::debug!(
                folder_id = %folder_id,
                checkpoint = ?diff.checkpoint,
                num_events = len,
                "folder",
            );

            let folder =
                self.0.folders_mut().get_mut(folder_id).ok_or_else(|| {
                    StorageError::FolderNotFound(*folder_id)
                })?;

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
                .any(|e| matches!(e, WriteEvent::SetVaultFlags(_)));

            // If the flags changed ensure the in-memory summaries
            // are up to date
            if flags_changed {
                self.0.load_folders().await?;
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
impl<T> SyncStorage for SyncImpl<T>
where
    T: StorageEventLogs<Error = Error>
        + ClientAccountStorage
        + ClientDeviceStorage
        + ClientFolderStorage,
{
    fn is_client_storage(&self) -> bool {
        true
    }
}
