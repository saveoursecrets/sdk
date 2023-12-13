//! Synchronization helpers.
use crate::{
    encode,
    events::{AccountEvent, EventReducer, FolderEventLog, WriteEvent},
    storage::Storage,
    vfs, Error, Paths, Result,
};

use std::collections::HashMap;

use crate::sync::{ChangeSet, FolderPatch, SyncDiff, SyncStatus, ApplyDiffOptions, AccountDiff};

impl Storage {
    /// Create a new vault file on disc and the associated
    /// event log.
    ///
    /// If a vault file already exists it is overwritten if an
    /// event log exists it is truncated and the single create
    /// vault event is written.
    ///
    /// Intended to be used by a server to create the identity
    /// vault and event log when a new account is created.
    pub async fn initialize_account(
        paths: &Paths,
        identity_patch: &FolderPatch,
    ) -> Result<FolderEventLog> {
        let events: Vec<&WriteEvent> = identity_patch.into();

        let mut event_log =
            FolderEventLog::new_folder(paths.identity_events()).await?;
        event_log.clear().await?;
        event_log.apply(events).await?;

        let vault = EventReducer::new()
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
        account_data: &ChangeSet,
    ) -> Result<()> {
        {
            let mut writer = self.account_log.write().await;
            writer.patch_unchecked(&account_data.account).await?;
        }

        for (id, folder) in &account_data.folders {
            let vault_path = self.paths.vault_path(id);
            let events_path = self.paths.event_log_path(id);

            let mut event_log =
                FolderEventLog::new_folder(events_path).await?;
            event_log.patch_unchecked(folder).await?;

            let vault = EventReducer::new()
                .reduce(&event_log)
                .await?
                .build(false)
                .await?;

            let summary = vault.summary().clone();

            let buffer = encode(&vault).await?;
            vfs::write(vault_path, buffer).await?;

            self.cache_mut().insert(*id, event_log);
            self.state.add_summary(summary);
        }

        Ok(())
    }

    /// Get the sync status.
    pub async fn sync_status(&self) -> Result<SyncStatus> {
        let identity = {
            let reader = self.identity_log.read().await;
            reader.tree().commit_state()?
        };

        let account = {
            let reader = self.account_log.read().await;
            reader.tree().commit_state()?
        };

        let summaries = self.state.summaries();
        let mut folders = HashMap::new();
        for summary in summaries {
            let event_log = self
                .cache
                .get(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;

            let last_commit =
                event_log.tree().last_commit().ok_or(Error::NoRootCommit)?;
            let head = event_log.tree().head()?;
            folders.insert(*summary.id(), (last_commit, head));
        }
        Ok(SyncStatus {
            identity,
            account,
            folders,
        })
    }

    /// Change set of all event logs.
    ///
    /// Used by network aware implementations to send
    /// account information to a server.
    pub async fn change_set(&self) -> Result<ChangeSet> {
        let identity = {
            let reader = self.identity_log.read().await;
            reader.diff(None).await?
        };

        let account = {
            let reader = self.account_log.read().await;
            reader.diff(None).await?
        };

        let mut folders = HashMap::new();
        for summary in self.state.summaries() {
            let folder_log = self
                .cache
                .get(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            folders.insert(*summary.id(), folder_log.diff(None).await?);
        }

        Ok(ChangeSet {
            identity,
            account,
            folders,
        })
    }

    /// Apply a diff to this storage.
    pub async fn apply_diff(
        &mut self,
        diff: &SyncDiff,
        options: ApplyDiffOptions,
    ) -> Result<()> {
        if let Some(diff) = &diff.identity {
            let mut writer = self.identity_log.write().await;
            writer.patch_checked(&diff.before, &diff.patch).await?;
        }

        if let Some(diff) = &diff.account {
            if !options.replay_account_events {
                let mut writer = self.account_log.write().await;
                writer.patch_checked(&diff.before, &diff.patch).await?;
            } else {
                self.replay_account_events(diff).await?;
            }
        }

        for (id, diff) in &diff.folders {
            let log = self
                .cache
                .get_mut(id)
                .ok_or_else(|| Error::CacheNotAvailable(*id))?;

            log.patch_checked(&diff.before, &diff.patch).await?;
        }

        Ok(())
    }

    async fn replay_account_events(
        &mut self,
        diff: &AccountDiff,
    ) -> Result<()> {
        // Apply account-level events to this storage
        for event in diff.patch.iter() {
            match &event {
                AccountEvent::CreateFolder(id, buf) => {
                    self.import_folder(buf, None).await?;
                }
                //AccountEvent::UpdateFolder(id, buf) => {
                AccountEvent::UpdateFolder(id) => {
                    println!("HANDLE UPDATE FOLDER EVENT");
                    //self.import_folder(buf, None).await?;
                }
                AccountEvent::DeleteFolder(id) => {
                    let summary = self.find(|s| s.id() == id).cloned();
                    if let Some(summary) = &summary {
                        self.delete_folder(summary).await?;
                    }
                }
                _ => {
                    println!("todo! : apply other account events")
                }
            }
        }

        Ok(())
    }
}
