//! Bridge between a local provider and a remote server.
use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use async_trait::async_trait;
use http::StatusCode;

use sos_sdk::{
    account::AccountStatus,
    commit::{
        CommitHash, CommitProof, CommitRelationship, CommitTree, SyncInfo,
    },
    crypto::AccessKey,
    decode, encode,
    events::{
        AuditLogFile, ChangeAction, ChangeNotification, EventLogFile,
        EventReducer, Patch, ReadEvent, WriteEvent,
    },
    passwd::diceware::generate_passphrase,
    storage::UserPaths,
    vault::{
        secret::{Secret, SecretId, SecretMeta},
        Summary, Vault, VaultBuilder, VaultFlags, VaultId,
    },
    vfs,
};

use std::{
    any::Any,
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    client::{
        provider::{LocalProvider, ProviderState},
        RemoteSync,
    },
    patch, retry,
};

/// Bridge between a local provider and a remote.
#[derive(Clone)]
pub struct RemoteProvider {
    /// Local provider.
    local: Arc<RwLock<LocalProvider>>,
    /// Client to use for remote communication.
    remote: RpcClient,
}

impl RemoteProvider {
    /// Create a new remote provider.
    pub fn new(
        local: Arc<RwLock<LocalProvider>>,
        remote: RpcClient,
    ) -> RemoteProvider {
        Self { local, remote }
    }

    /// Local provider.
    pub fn local(&self) -> Arc<RwLock<LocalProvider>> {
        Arc::clone(&self.local)
    }
}

/*
impl RemoteProvider {
    provider_impl!();

    async fn create_vault_or_account(
        &mut self,
        name: Option<String>,
        key: Option<AccessKey>,
        is_account: bool,
    ) -> Result<(WriteEvent<'static>, AccessKey, Summary)> {
        let key = if let Some(key) = key {
            key
        } else {
            let (passphrase, _) = generate_passphrase()?;
            AccessKey::Password(passphrase)
        };

        let mut builder = VaultBuilder::new();
        if let Some(name) = name {
            builder = builder.public_name(name);
        }
        if is_account {
            builder = builder.flags(VaultFlags::DEFAULT);
        }

        let vault = match &key {
            AccessKey::Password(password) => {
                builder.password(password.clone(), None).await?
            }
            AccessKey::Identity(id) => {
                builder.shared(id, vec![], true).await?
            }
        };

        let buffer = encode(&vault).await?;

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
        self.create_cache_entry(&summary, Some(vault)).await?;

        let event = WriteEvent::CreateVault(Cow::Owned(buffer));
        Ok((event, key, summary))
    }

    async fn import_vault(
        &mut self,
        buffer: Vec<u8>,
    ) -> Result<(WriteEvent<'static>, Summary)> {
        let vault: Vault = decode(&buffer).await?;
        let summary = vault.summary().clone();

        let (status, _) =
            retry!(|| self.client.create_vault(buffer.clone()), self.client);

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        /*
        if self.state().mirror() {
            self.write_vault_file(&summary, &buffer).await?;
        }

        // Add the summary to the vaults we are managing
        self.state_mut().add_summary(summary.clone());

        // Initialize the local cache for the event log
        self.create_cache_entry(&summary, Some(vault)).await?;
        */

        Ok((WriteEvent::CreateVault(Cow::Owned(buffer)), summary))
    }

    async fn create_account_from_buffer(
        &mut self,
        buffer: Vec<u8>,
    ) -> Result<(WriteEvent<'static>, Summary)> {
        let vault: Vault = decode(&buffer).await?;
        let summary = vault.summary().clone();

        let (status, _) = retry!(
            || self.client.create_account(buffer.clone()),
            self.client
        );

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        /*
        if self.state().mirror() {
            self.write_vault_file(&summary, &buffer).await?;
        }

        // Add the summary to the vaults we are managing
        self.state_mut().add_summary(summary.clone());

        // Initialize the local cache for the event log
        self.create_cache_entry(&summary, Some(vault)).await?;
        */

        Ok((WriteEvent::CreateVault(Cow::Owned(buffer)), summary))
    }

    async fn handshake(&mut self) -> Result<()> {
        Ok(self.client.handshake().await?)
    }

    async fn account_status(&mut self) -> Result<AccountStatus> {
        let (_, status) =
            retry!(|| self.client.account_status(), self.client);
        status.ok_or(Error::NoAccountStatus)
    }

    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<WriteEvent<'static>> {
        let event =
            WriteEvent::SetVaultName(Cow::Borrowed(name)).into_owned();
        patch!(self, summary, vec![event.clone()])?;

        for item in self.state.summaries_mut().iter_mut() {
            if item.id() == summary.id() {
                item.set_name(name.to_string());
            }
        }
        Ok(event)
    }

    async fn remove_vault(
        &mut self,
        summary: &Summary,
    ) -> Result<WriteEvent<'static>> {
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

        Ok(WriteEvent::DeleteVault)
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
        events: Vec<WriteEvent<'a>>,
    ) -> Result<()> {
        let (event_log, _) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        // Send the new vault to the server
        let buffer = encode(vault).await?;
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
        event_log.clear().await?;
        event_log
            .apply(events, Some(CommitHash(*server_proof.root())))
            .await?;

        Ok(())
    }

    async fn reduce_event_log(&mut self, summary: &Summary) -> Result<Vault> {
        let event_log_file = self
            .cache
            .get_mut(summary.id())
            .map(|(w, _)| w)
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        Ok(EventReducer::new()
            .reduce(event_log_file)
            .await?
            .build()
            .await?)
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
        let self_change = self.client.public_key() == change.public_key();
        let actions = sync::handle_change(self, change).await?;
        Ok((self_change, actions))
    }

    // Override this so we also call patch() which will ensure
    // the remote adds the event to it's audit log.
    async fn read_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, ReadEvent)> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let _summary = keeper.summary().clone();
        let (meta, secret, event) =
            keeper.read(id).await?.ok_or(Error::SecretNotFound(*id))?;
        Ok((meta, secret, event))
    }
}
*/

/// Sync helper functions.
impl RemoteProvider {
    /// Perform the noise protocol handshake.
    pub async fn handshake(&self) -> Result<()> {
        Ok(self.remote.handshake().await?)
    }

    /// Get account status from remote.
    pub async fn account_status(&self) -> Result<AccountStatus> {
        let (_, status) =
            retry!(|| self.remote.account_status(), self.remote);
        status.ok_or(Error::NoAccountStatus)
    }

    /// Create an account on the remote.
    async fn create_account(&self, buffer: Vec<u8>) -> Result<()> {
        let vault: Vault = decode(&buffer).await?;
        let summary = vault.summary().clone();
        let (status, _) = retry!(
            || self.remote.create_account(buffer.clone()),
            self.remote
        );

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        Ok(())
    }

    /// Import a vault into an account that already exists on the remote.
    async fn import_vault(&self, buffer: Vec<u8>) -> Result<()> {
        let vault: Vault = decode(&buffer).await?;
        let summary = vault.summary().clone();
        let (status, _) =
            retry!(|| self.remote.create_vault(buffer.clone()), self.remote);
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;
        Ok(())
    }

    async fn sync_pull(
        &self,
        last_commit: Option<&CommitHash>,
        client_proof: &CommitProof,
        folder: &Summary,
    ) -> Result<()> {
        
        let last_commit = last_commit.ok_or_else(|| Error::NoRootCommit)?;

        let (status, (num_events, body)) = retry!(
            || self.remote.diff(folder.id(), last_commit, client_proof),
            self.remote
        );
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        if num_events > 0 {
            let patch: Patch = decode(&body).await?;
            let events = patch.into_events().await?;
            let mut writer = self.local.write().await;
            writer.patch(folder, events).await?;
        }

        Ok(())
    }

    /// Create an account on the remote.
    async fn sync_create_remote_account(&self) -> Result<()> {
        let folder_buffer = {
            let local = self.local.read().await;
            let default_folder = local
                .state()
                .find(|s| s.flags().is_default())
                .ok_or(Error::NoDefaultFolder)?
                .clone();

            let folder_path = local.vault_path(&default_folder);
            vfs::read(folder_path).await?
        };

        // Create the account and default folder on the remote
        self.create_account(folder_buffer).await?;

        // Import other folders into the remote
        let other_folders: Vec<Summary> = {
            let local = self.local.read().await;
            local
                .state()
                .summaries()
                .into_iter()
                .filter(|s| !s.flags().is_default())
                .map(|s| s.clone())
                .collect()
        };

        for folder in other_folders {
            let folder_buffer = {
                let local = self.local.read().await;
                let folder_path = local.vault_path(&folder);
                vfs::read(folder_path).await?
            };

            self.import_vault(folder_buffer).await?;
        }

        // FIXME: import files here!

        Ok(())
    }

    async fn patch(
        &self,
        before_last_commit: Option<&CommitHash>,
        before_client_proof: &CommitProof,
        after_client_proof: &CommitProof,
        folder: &Summary,
        events: &[WriteEvent<'static>],
    ) -> Result<()> {
        let patch = {
            let reader = self.local.read().await;
            let event_log = reader
                .cache()
                .get(folder.id())
                .ok_or(Error::CacheNotAvailable(*folder.id()))?;
            event_log.patch_until(before_last_commit).await?
        };

        let (status, (server_proof, match_proof)) = retry!(
            || self.remote.apply_patch(
                folder.id(),
                before_client_proof,
                after_client_proof,
                &patch,
            ),
            self.remote
        );

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        Ok(())
    }
}

#[async_trait]
impl RemoteSync for RemoteProvider {
    async fn sync(&self) -> Result<()> {
        // Ensure our folder state is the latest version on disc
        {
            let mut local = self.local.write().await;
            local.load_vaults().await?;
        }

        let account_status = self.account_status().await?;
        if !account_status.exists {
            self.sync_create_remote_account().await
        } else {
            todo!("sync with existing account");
        }
    }

    async fn sync_before_apply_change(
        &self,
        last_commit: Option<&CommitHash>,
        client_proof: &CommitProof,
        folder: &Summary,
    ) -> Result<()> {
        self.sync_pull(last_commit, client_proof, folder).await
    }

    async fn sync_send_events(
        &self,
        before_last_commit: Option<&CommitHash>,
        before_client_proof: &CommitProof,
        after_client_proof: &CommitProof,
        folder: &Summary,
        events: &[WriteEvent<'static>],
    ) -> Result<()> {
        self.patch(
            before_last_commit, 
            before_client_proof,
            after_client_proof,
            folder,
            events,
        ).await?;
        Ok(())
    }

    async fn sync_receive_events(
        &self,
        events: &[WriteEvent<'static>],
    ) -> Result<()> {
        todo!();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
