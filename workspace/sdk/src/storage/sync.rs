//! Synchronization helpers.
use crate::{
    encode,
    events::{
        AccountEvent, EventLogExt, EventReducer, FolderEventLog, WriteEvent,
    },
    storage::Storage,
    sync::{
        AccountDiff, ChangeSet, FolderPatch, MergeOptions, SyncDiff, SyncStatus,
        FolderDiff,
    },
    vault::VaultId,
    vfs, Error, Paths, Result,
};

use std::collections::HashMap;

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
            FolderEventLog::new(paths.identity_events()).await?;
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

            let mut event_log = FolderEventLog::new(events_path).await?;
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

    /// Merge a diff into this storage.
    pub async fn merge_diff(
        &mut self,
        diff: &SyncDiff,
        options: MergeOptions,
    ) -> Result<usize> {
        let mut num_changes = 0;

        if let Some(diff) = &diff.identity {
            if !options.replay_identity_events {
                let mut writer = self.identity_log.write().await;
                writer.patch_checked(&diff.before, &diff.patch).await?;
            } else {
                self.replay_identity_events(diff).await?;
            }
            num_changes += diff.patch.len();
        }

        if let Some(diff) = &diff.account {
            if !options.replay_account_events {
                let mut writer = self.account_log.write().await;
                writer.patch_checked(&diff.before, &diff.patch).await?;
            } else {
                self.replay_account_events(diff).await?;
            }
            num_changes += diff.patch.len();
        }

        for (id, diff) in &diff.folders {
            let log = self
                .cache
                .get_mut(id)
                .ok_or_else(|| Error::CacheNotAvailable(*id))?;

            if !options.replay_folder_events {
                log.patch_checked(&diff.before, &diff.patch).await?;
                num_changes += diff.patch.len();
            } else {
                self.replay_folder_events(id, diff).await?;
            }
        }

        Ok(num_changes)
    }

    /// Apply identity-level events to this storage
    async fn replay_identity_events(
        &mut self,
        diff: &FolderDiff,
    ) -> Result<()> {
        for event in diff.patch.iter() {
            match event {
                WriteEvent::CreateSecret(secret_id, vault_commit) => {
                    /*
                    let hash = vault_commit.0.clone();
                    let entry = vault_commit.1.clone();
                    mirror.insert(*secret_id, hash, entry).await?;
                    */
                }
                WriteEvent::UpdateSecret(secret_id, vault_commit) => {
                    /*
                    let hash = vault_commit.0.clone();
                    let entry = vault_commit.1.clone();
                    mirror.update(secret_id, hash, entry).await?;
                    */
                }
                WriteEvent::SetVaultName(name) => {
                    /*
                    mirror.set_vault_name(name.to_owned()).await?;
                    */
                }
                WriteEvent::SetVaultMeta(meta) => {
                    /*
                    mirror.set_vault_meta(meta.clone()).await?;
                    */
                }
                WriteEvent::DeleteSecret(secret_id) => {
                    /*
                    mirror.delete(secret_id).await?;
                    */
                }
                _ => {} // Ignore CreateVault and Noop
            }
        }
        Ok(())
    }

    /// Apply account-level events to this storage
    async fn replay_account_events(
        &mut self,
        diff: &AccountDiff,
    ) -> Result<()> {
        for event in diff.patch.iter() {
            match &event {
                AccountEvent::CreateFolder(_, buf)
                | AccountEvent::UpdateFolder(_, buf)
                | AccountEvent::CompactFolder(_, buf)
                | AccountEvent::ChangeFolderPassword(_, buf) => {
                    self.import_folder(buf, None).await?;
                }
                AccountEvent::RenameFolder(id, name) => {
                    let summary = self.find(|s| s.id() == id).cloned();
                    if let Some(summary) = &summary {
                        self.rename_folder(summary, name).await?;
                    }
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

    /// Apply folder-level events to this storage
    async fn replay_folder_events(
        &mut self,
        id: &VaultId,
        diff: &FolderDiff,
    ) -> Result<()> {
        for event in diff.patch.iter() {
            match event {
                WriteEvent::CreateSecret(secret_id, vault_commit) => {
                    //todo!("decrypt and create secret");
                }
                WriteEvent::UpdateSecret(secret_id, vault_commit) => {
                    //todo!("decrypt and update secret");
                }
                WriteEvent::SetVaultName(name) => {
                    let summary = self.find(|s| s.id() == id).cloned();
                    if let Some(summary) = &summary {
                        self.rename_folder(summary, name).await?;
                    }
                }
                WriteEvent::SetVaultMeta(meta) => {
                    //todo!("decrypt and set vault meta");
                }
                WriteEvent::DeleteSecret(secret_id) => {
                    let summary = self.find(|s| s.id() == id).cloned();
                    if let Some(summary) = summary {
                        self.delete_secret(secret_id, summary.into()).await?;
                    }
                }
                _ => {} // Ignore CreateVault and Noop
            }
        }

        Ok(())
    }
}
