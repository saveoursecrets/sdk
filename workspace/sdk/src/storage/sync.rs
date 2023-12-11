//! Synchronization helpers.
use crate::{
    commit::{CommitHash, CommitState, CommitTree},
    constants::{EVENT_LOG_EXT, VAULT_EXT},
    crypto::AccessKey,
    decode, encode,
    events::{
        AccountEvent, AccountEventLog, AuditEvent, Event, EventKind,
        EventReducer, FolderEventLog, ReadEvent, WriteEvent,
    },
    identity::FolderKeys,
    passwd::{diceware::generate_passphrase, ChangePassword},
    signer::ecdsa::Address,
    storage::AccountPack,
    storage::Storage,
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow},
        FolderRef, Gatekeeper, Header, Summary, Vault, VaultAccess,
        VaultBuilder, VaultCommit, VaultFlags, VaultId, VaultMeta,
        VaultWriter,
    },
    vfs, Error, Paths, Result, Timestamp,
};

use secrecy::SecretString;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{span, Level};

use crate::sync::{AccountStatus, ChangeSet, FolderPatch};

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

    /// Get the account status.
    pub async fn account_status(&self) -> Result<AccountStatus> {
        let account = {
            let reader = self.account_log.read().await;
            if reader.tree().is_empty() {
                None
            } else {
                Some(reader.tree().head()?)
            }
        };

        let identity = {
            let identity_log = self.identity_log.read().await;
            identity_log.tree().head()?
        };

        let summaries = self.state.summaries();
        let mut proofs = HashMap::new();
        for summary in summaries {
            let event_log = self
                .cache
                .get(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            let last_commit =
                event_log.last_commit().await?.ok_or(Error::NoRootCommit)?;
            let head = event_log.tree().head()?;
            proofs.insert(*summary.id(), (last_commit, head));
        }
        Ok(AccountStatus {
            exists: true,
            identity,
            account,
            proofs,
        })
    }

    /// Change set of all event logs.
    ///
    /// Used by network aware implementations to send
    /// account information to a server.
    pub async fn change_set(&self) -> Result<ChangeSet> {
        let address = self.address.clone();

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
            address,
            identity,
            account,
            folders,
        })
    }
}
