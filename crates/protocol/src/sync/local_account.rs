//! Implements merging into a local account.
use crate::{
    sdk::{
        account::{Account, LocalAccount},
        commit::{CommitState, CommitTree, Comparison},
        decode,
        events::{
            AccountDiff, AccountEvent, CheckedPatch, EventLogExt, FolderDiff,
            LogEvent,
        },
        storage::StorageEventLogs,
        vault::{Vault, VaultId},
        Error, Result,
    },
    FolderMerge, FolderMergeOptions, ForceMerge, IdentityFolderMerge, Merge,
    MergeOutcome, SyncStatus, SyncStorage,
};
use async_trait::async_trait;
use indexmap::IndexMap;

use crate::sdk::events::{DeviceDiff, DeviceReducer};

#[cfg(feature = "files")]
use crate::sdk::events::FileDiff;

#[async_trait]
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

        self.user_mut()?.identity_mut()?.force_merge(diff).await?;
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

        let event_log = self.account_log().await?;
        let mut event_log = event_log.write().await;
        event_log.patch_replace(diff).await?;

        outcome.identity = len;
        outcome.changes += len;

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
        event_log.patch_replace(diff).await?;

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

        let storage = self.storage().await?;
        let mut storage = storage.write().await;

        let folder = storage
            .cache_mut()
            .get_mut(folder_id)
            .ok_or_else(|| Error::CacheNotAvailable(*folder_id))?;
        folder.force_merge(diff).await?;

        outcome.folders.insert(*folder_id, len);
        outcome.changes += len;

        Ok(())
    }
}

#[async_trait]
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

        let checked_patch =
            self.user_mut()?.identity_mut()?.merge(diff).await?;

        if let CheckedPatch::Success(_) = &checked_patch {
            outcome.identity = len;
            outcome.changes += len;
        }

        Ok(checked_patch)
    }

    async fn compare_identity(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let log = self.identity_log().await?;
        let event_log = log.read().await;
        event_log.tree().compare(&state.1)
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
            let account_log = self.account_log().await?;
            let mut event_log = account_log.write().await;
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

            outcome.account = diff.patch.len() as u64;
            outcome.changes += diff.patch.len() as u64;
        }

        Ok(checked_patch)
    }

    async fn compare_account(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let log = self.account_log().await?;
        let event_log = log.read().await;
        event_log.tree().compare(&state.1)
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
            let storage = self.storage().await?;
            let storage = storage.read().await;
            let mut event_log = storage.device_log.write().await;
            event_log
                .patch_checked(&diff.checkpoint, &diff.patch)
                .await?
        };

        if let CheckedPatch::Success(_) = &checked_patch {
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

            outcome.device = diff.patch.len() as u64;
            outcome.changes += diff.patch.len() as u64;
        } else {
            // FIXME: handle conflict situation
            println!("todo! device patch could not be merged");
        }

        Ok(checked_patch)
    }

    async fn compare_device(
        &self,
        state: &CommitState,
    ) -> Result<Comparison> {
        let log = self.device_log().await?;
        let event_log = log.read().await;
        event_log.tree().compare(&state.1)
    }

    #[cfg(feature = "files")]
    async fn merge_files(
        &mut self,
        diff: FileDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        use crate::sdk::events::FileReducer;
        tracing::debug!(
            checkpoint = ?diff.checkpoint,
            num_events = diff.patch.len(),
            "files",
        );

        let storage = self.storage().await?;
        let storage = storage.read().await;
        let mut event_log = storage.file_log.write().await;

        // File events may not have a root commit
        let is_init_diff = diff.last_commit.is_none();
        let (checked_patch, external_files) =
            if is_init_diff && event_log.tree().is_empty() {
                event_log.patch_unchecked(&diff.patch).await?;
                let reducer = FileReducer::new(&event_log);
                let external_files = reducer.reduce(None).await?;

                let proof = event_log.tree().head()?;
                (CheckedPatch::Success(proof), external_files)
            } else {
                let checked_patch = event_log
                    .patch_checked(&diff.checkpoint, &diff.patch)
                    .await?;
                let reducer = FileReducer::new(&event_log);
                let external_files =
                    reducer.reduce(diff.last_commit.as_ref()).await?;
                (checked_patch, external_files)
            };

        outcome.external_files = external_files;

        if let CheckedPatch::Success(_) = &checked_patch {
            outcome.files = diff.patch.len() as u64;
            outcome.changes += diff.patch.len() as u64;
        }

        Ok(checked_patch)
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
        diff: FolderDiff,
        outcome: &mut MergeOutcome,
    ) -> Result<CheckedPatch> {
        let len = diff.patch.len() as u64;

        let storage = self.storage().await?;
        let mut storage = storage.write().await;

        #[cfg(feature = "search")]
        let search = {
            let index = storage.index.as_ref().ok_or(Error::NoSearchIndex)?;
            index.search()
        };

        tracing::debug!(
            folder_id = %folder_id,
            checkpoint = ?diff.checkpoint,
            num_events = len,
            "folder",
        );

        let folder = storage
            .cache_mut()
            .get_mut(folder_id)
            .ok_or_else(|| Error::CacheNotAvailable(*folder_id))?;

        let checked_patch = {
            #[cfg(feature = "search")]
            {
                let mut search = search.write().await;
                folder
                    .merge(
                        diff,
                        FolderMergeOptions::Search(*folder_id, &mut search),
                    )
                    .await?
            }

            #[cfg(not(feature = "search"))]
            {
                folder
                    .merge(
                        diff,
                        FolderMergeOptions::Urn(
                            *folder_id,
                            &mut Default::default(),
                        ),
                    )
                    .await?
            }
        };

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
        // NOTE: the order for computing the cumulative
        // NOTE: root hash must be identical to the logic
        // NOTE: in the server implementation and the folders
        // NOTE: collection must be sorted so that the folders
        // NOTE: root hash is deterministic

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
        let mut folder_roots: Vec<(&VaultId, [u8; 32])> = Vec::new();
        for summary in &summaries {
            let folder = storage
                .cache()
                .get(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;

            let commit_state = folder.commit_state().await?;
            folder_roots.push((summary.id(), commit_state.1.root().into()));
            folders.insert(*summary.id(), commit_state);
        }

        // Compute a root hash of all the trees for an account
        let mut root_tree = CommitTree::new();
        let mut root_commits = vec![
            identity.1.root().into(),
            account.1.root().into(),
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
            device,
            #[cfg(feature = "files")]
            files,
            folders,
        })
    }
}
