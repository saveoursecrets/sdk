//! Wrapper for the RPC client that handles authentication
//! and retries when an unauthorized response is returned.
use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use async_trait::async_trait;
use http::StatusCode;

use sos_sdk::{
    account::AccountStatus,
    commit::{CommitHash, CommitRelationship, CommitTree, SyncInfo},
    crypto::AccessKey,
    decode, encode,
    events::{AuditLogFile, ChangeAction, ChangeNotification, WriteEvent},
    events::{EventLogFile, EventReducer, ReadEvent},
    passwd::diceware::generate_passphrase,
    patch::PatchFile,
    storage::UserPaths,
    vault::{
        secret::{Secret, SecretId, SecretMeta},
        Summary, Vault, VaultBuilder, VaultFlags, VaultId,
    },
    vfs,
};

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    client::{
        provider::{sync, ProviderState, StorageProvider},
        RemoteSync,
    },
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
    paths: UserPaths,

    /// Data for the cache.
    cache: HashMap<Uuid, (EventLogFile, PatchFile)>,

    /// Client to use for remote communication.
    client: RpcClient,

    /// Audit log for this provider.
    audit_log: Arc<RwLock<AuditLogFile>>,
}

impl RemoteProvider {
    /// Create new node cache backed by files on disc.
    pub async fn new(
        client: RpcClient,
        paths: UserPaths,
    ) -> Result<RemoteProvider> {
        if !vfs::metadata(paths.documents_dir()).await?.is_dir() {
            return Err(Error::NotDirectory(
                paths.documents_dir().to_path_buf(),
            ));
        }

        paths.ensure().await?;

        let audit_log = Arc::new(RwLock::new(
            AuditLogFile::new(paths.audit_file()).await?,
        ));

        Ok(Self {
            state: ProviderState::new(true),
            cache: Default::default(),
            client,
            paths,
            audit_log,
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

    /*
    async fn load_vaults(&mut self) -> Result<&[Summary]> {
        let (_, summaries) =
            retry!(|| self.client.list_vaults(), self.client);

        self.load_caches(&summaries).await?;

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
    */

    async fn patch(
        &mut self,
        summary: &Summary,
        events: Vec<WriteEvent<'static>>,
    ) -> Result<()> {
        patch!(self, summary, events)?;
        Ok(())
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

/// Sync helper functions.
impl RemoteProvider {
    /// Create an account on the remote.
    async fn sync_create_remote_account(&mut self) -> Result<()> {
        let default_folder = self
            .state
            .find(|s| s.flags().is_default())
            .ok_or(Error::NoDefaultFolder)?;

        let folder_path = self.vault_path(&default_folder);
        let folder_buffer = vfs::read(folder_path).await?;

        // Create the account and default folder on the remote
        self.create_account_from_buffer(folder_buffer).await?;

        // Import other folders into the remote
        let other_folders: Vec<Summary> = self
            .state
            .summaries()
            .into_iter()
            .filter(|s| !s.flags().is_default())
            .map(|s| s.clone())
            .collect();

        for folder in other_folders {
            let folder_path = self.vault_path(&folder);
            let folder_buffer = vfs::read(folder_path).await?;
            self.import_vault(folder_buffer).await?;
        }

        // FIXME: import files here!

        Ok(())
    }
}

#[async_trait]
impl RemoteSync for RemoteProvider {
    async fn sync(&mut self) -> Result<()> {
        // Ensure our folder state is the latest version on disc
        self.load_vaults().await?;

        let account_status = self.account_status().await?;
        if !account_status.exists {
            self.sync_create_remote_account().await
        } else {
            todo!("sync with existing account");
        }
    }

    async fn sync_local_events(&self, events: &[WriteEvent]) -> Result<()> {
        todo!();
    }
}
