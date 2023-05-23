//! Wrapper for the RPC client that handles authentication
//! and retries when an unauthorized response is returned.
use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use async_trait::async_trait;
use http::StatusCode;
use secrecy::SecretString;
use sos_sdk::{
    commit::{CommitHash, CommitRelationship, CommitTree, SyncInfo},
    decode, encode,
    events::{ChangeAction, ChangeNotification, SyncEvent},
    events::{EventLogFile, EventReducer},
    patch::PatchFile,
    storage::StorageDirs,
    vault::{
        secret::{Secret, SecretId, SecretMeta},
        Summary, Vault,
    },
    vfs, Timestamp,
};

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};
use uuid::Uuid;

use crate::{
    client::provider::{sync, ProviderState, StorageProvider},
    patch, provider_impl, retry,
};

/// Local data cache for a node.
///
/// May be backed by files on disc or in-memory implementations
/// for use in webassembly.
pub struct RemoteProvider {
    /// State of this node.
    state: ProviderState,

    /// Directories for file storage.
    ///
    /// For memory based storage the paths will be empty.
    dirs: StorageDirs,

    /// Data for the cache.
    cache: HashMap<Uuid, (EventLogFile, PatchFile)>,

    /// Client to use for remote communication.
    client: RpcClient,
}

impl RemoteProvider {
    /// Create new node cache backed by files on disc.
    pub fn new(
        client: RpcClient,
        dirs: StorageDirs,
    ) -> Result<RemoteProvider> {
        if !dirs.documents_dir().is_dir() {
            return Err(Error::NotDirectory(
                dirs.documents_dir().to_path_buf(),
            ));
        }

        Ok(Self {
            state: ProviderState::new(true),
            cache: Default::default(),
            client,
            dirs,
        })
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StorageProvider for RemoteProvider {
    provider_impl!();

    async fn create_vault_or_account(
        &mut self,
        name: Option<String>,
        passphrase: Option<SecretString>,
        is_account: bool,
    ) -> Result<(SecretString, Summary)> {
        let (passphrase, vault, buffer) =
            Vault::new_buffer(name, passphrase, None)?;

        let status = if is_account {
            let (status, _) = retry!(
                || self.client.create_account(buffer.clone()),
                self.client
            );
            status
        } else {
            let (status, _) = retry!(
                || self.client.create_vault(buffer.clone()),
                self.client
            );
            status
        };

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        let summary = vault.summary().clone();

        if self.state().mirror() {
            self.write_vault_file(&summary, &buffer).await?;
        }

        // Add the summary to the vaults we are managing
        self.state_mut().add_summary(summary.clone());

        // Initialize the local cache for the event log
        self.create_cache_entry(&summary, Some(vault))?;

        Ok((passphrase, summary))
    }

    async fn import_vault(&mut self, buffer: Vec<u8>) -> Result<Summary> {
        let vault: Vault = decode(&buffer)?;
        let summary = vault.summary().clone();

        let (status, _) =
            retry!(|| self.client.create_vault(buffer.clone()), self.client);

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        if self.state().mirror() {
            self.write_vault_file(&summary, &buffer).await?;
        }

        // Add the summary to the vaults we are managing
        self.state_mut().add_summary(summary.clone());

        // Initialize the local cache for the event log
        self.create_cache_entry(&summary, Some(vault))?;

        Ok(summary)
    }

    async fn create_account_with_buffer(
        &mut self,
        buffer: Vec<u8>,
    ) -> Result<Summary> {
        let vault: Vault = decode(&buffer)?;
        let summary = vault.summary().clone();

        let (status, _) = retry!(
            || self.client.create_account(buffer.clone()),
            self.client
        );

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        if self.state().mirror() {
            self.write_vault_file(&summary, &buffer).await?;
        }

        // Add the summary to the vaults we are managing
        self.state_mut().add_summary(summary.clone());

        // Initialize the local cache for the event log
        self.create_cache_entry(&summary, Some(vault))?;

        Ok(summary)
    }

    async fn authenticate(&mut self) -> Result<()> {
        Ok(self.client.authenticate().await?)
    }

    async fn load_vaults(&mut self) -> Result<&[Summary]> {
        let (_, summaries) =
            retry!(|| self.client.list_vaults(), self.client);

        self.load_caches(&summaries)?;

        // Find empty event logs which need to pull from remote
        let mut needs_pull = Vec::new();
        for summary in &summaries {
            let (event_log_file, _) = self
                .cache
                .get(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            let length = event_log_file.tree().len();

            // Got an empty tree which can happen if an
            // existing user signs in with a new cache directory
            // we need to fetch the entire event log from remote
            if length == 0 {
                needs_pull.push(summary.clone());
            }
        }

        self.state.set_summaries(summaries);

        for summary in needs_pull {
            let (event_log_file, _) = self
                .cache
                .get_mut(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            sync::pull_event_log(&mut self.client, &summary, event_log_file)
                .await?;
        }

        Ok(self.vaults())
    }

    async fn patch(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'static>>,
    ) -> Result<()> {
        patch!(self, summary, events)
    }

    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<()> {
        let event = SyncEvent::SetVaultName(Cow::Borrowed(name));

        patch!(self, summary, vec![event.into_owned()])?;

        for item in self.state.summaries_mut().iter_mut() {
            if item.id() == summary.id() {
                item.set_name(name.to_string());
            }
        }
        Ok(())
    }

    async fn remove_vault(&mut self, summary: &Summary) -> Result<()> {
        // Attempt to delete on the remote server
        let (status, _) =
            retry!(|| self.client.delete_vault(summary.id()), self.client);
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        // Remove the files
        self.remove_vault_file(summary).await?;

        // Remove local state
        self.remove_local_cache(summary)?;
        Ok(())
    }

    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        let (event_log_file, _) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        let (compact_event_log, old_size, new_size) =
            event_log_file.compact().await?;

        // Need to recreate the event log file and load the updated
        // commit tree
        *event_log_file = compact_event_log;

        // Refresh in-memory vault and mirrored copy
        self.refresh_vault(summary, None).await?;

        // Push changes to the remote
        self.push(summary, true).await?;

        Ok((old_size, new_size))
    }

    /// Update an existing vault by saving the new vault
    /// on a remote node.
    async fn update_vault<'a>(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<SyncEvent<'a>>,
    ) -> Result<()> {
        let (event_log, _) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        // Send the new vault to the server
        let buffer = encode(vault)?;
        let (status, server_proof) = retry!(
            || self.client.save_vault(summary.id(), buffer.clone()),
            self.client
        );
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        let server_proof = server_proof.ok_or(Error::ServerProof)?;

        // Apply the new event log events to our local event log log
        event_log.clear()?;
        event_log.apply(events, Some(CommitHash(*server_proof.root())))?;

        Ok(())
    }

    fn reduce_event_log(&mut self, summary: &Summary) -> Result<Vault> {
        let event_log_file = self
            .cache
            .get_mut(summary.id())
            .map(|(w, _)| w)
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        Ok(EventReducer::new().reduce(event_log_file)?.build()?)
    }

    async fn pull(
        &mut self,
        summary: &Summary,
        force: bool,
    ) -> Result<SyncInfo> {
        if force {
            self.backup_vault_file(summary).await?;
        }

        let (event_log_file, patch_file) =
            self.cache
                .get_mut(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        if force {
            vfs::remove_file(event_log_file.path()).await?;
        }

        sync::pull(
            &mut self.client,
            summary,
            event_log_file,
            patch_file,
            force,
        )
        .await
    }

    async fn push(
        &mut self,
        summary: &Summary,
        force: bool,
    ) -> Result<SyncInfo> {
        let (event_log_file, patch_file) =
            self.cache
                .get_mut(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        sync::push(
            &mut self.client,
            summary,
            event_log_file,
            patch_file,
            force,
        )
        .await
    }

    async fn status(
        &mut self,
        summary: &Summary,
    ) -> Result<(CommitRelationship, Option<usize>)> {
        let (event_log_file, patch_file) = self
            .cache
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        sync::status(&mut self.client, summary, event_log_file, patch_file)
            .await
    }

    async fn handle_change(
        &mut self,
        change: ChangeNotification,
    ) -> Result<(bool, HashSet<ChangeAction>)> {
        // Was this change notification triggered by us?
        let self_change = match self.client.session_id() {
            Ok(id) => &id == change.session_id(),
            // Maybe the session is no longer available
            Err(_) => false,
        };

        let actions = sync::handle_change(self, change).await?;
        Ok((self_change, actions))
    }

    // Override this so we also call patch() which will ensure
    // the remote adds the event to it's audit log.
    async fn read_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, SyncEvent<'_>)> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        let (meta, secret, event) =
            keeper.read(id)?.ok_or(Error::SecretNotFound(*id))?;
        let event = event.into_owned();

        // If patching fails then we drop an audit log entry
        // however we don't want this failure to interrupt the client
        // so we sevent_loglow the error in this case
        let _ = self.patch(&summary, vec![event.clone()]).await;

        Ok((meta, secret, event))
    }
}
