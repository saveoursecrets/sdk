//! Storage provider trait.

use async_trait::async_trait;

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::Arc,
};

use sos_sdk::{
    account::{AccountStatus, ImportedAccount, NewAccount},
    commit::{
        CommitHash, CommitProof, CommitRelationship, CommitTree, SyncInfo,
    },
    constants::{EVENT_LOG_EXT, PATCH_EXT, VAULT_EXT},
    crypto::{AccessKey, KeyDerivation, PrivateKey},
    decode, encode,
    events::{
        AuditEvent, AuditLogFile, ChangeAction, ChangeNotification, Event,
        EventKind, EventLogFile, ReadEvent, WriteEvent,
    },
    passwd::ChangePassword,
    patch::PatchFile,
    search::SearchIndex,
    signer::ecdsa::{BoxedEcdsaSigner, Address},
    storage::{UserPaths, AppPaths},
    vault::{
        secret::{Secret, SecretData, SecretId, SecretMeta},
        Gatekeeper, Header, Summary, Vault, VaultId,
    },
    mpc::Keypair,
    vfs, Timestamp,
};

use tokio::sync::RwLock;

use sos_sdk::account::RestoreTargets;

use crate::client::{Error, RemoteSync, Result, user::Origin, net::RpcClient};

/// Create a new remote provider.
pub async fn new_remote_provider(
    origin: &Origin,
    signer: BoxedEcdsaSigner,
    keypair: Keypair,
) -> Result<(RemoteProvider, Address)> {
    let data_dir = AppPaths::data_dir().map_err(|_| Error::NoCache)?;
    let address = signer.address()?;
    let client =
        RpcClient::new(
            origin.url.clone(),
            origin.public_key.clone(),
            signer,
            keypair,
        )?;
    let dirs = UserPaths::new(data_dir, &address.to_string());
    Ok((RemoteProvider::new(client, dirs).await?, address))
}

/// Create a new local provider.
pub async fn new_local_provider(
    signer: BoxedEcdsaSigner,
) -> Result<(LocalProvider, Address)> {
    let data_dir = AppPaths::data_dir().map_err(|_| Error::NoCache)?;
    let address = signer.address()?;
    let dirs = UserPaths::new(data_dir, &address.to_string());
    Ok((LocalProvider::new(dirs).await?, address))
}

pub(crate) fn assert_proofs_eq(
    client_proof: &CommitProof,
    server_proof: &CommitProof,
) -> Result<()> {
    if client_proof.root != server_proof.root {
        let client = CommitHash(client_proof.root);
        let server = CommitHash(server_proof.root);
        Err(Error::RootHashMismatch(client, server))
    } else {
        Ok(())
    }
}

mod local_provider;
mod macros;
mod provider_factory;
mod remote_provider;
mod state;
mod sync;

pub use local_provider::LocalProvider;
#[cfg(not(target_arch = "wasm32"))]
pub use provider_factory::spawn_changes_listener;
pub use remote_provider::RemoteProvider;

pub use state::ProviderState;

/// Generic boxed provider.
pub type BoxedProvider = Box<dyn StorageProvider + Send + Sync + 'static>;

/// Trait for storage providers.
///
/// Note we need `Sync` and `Send` super traits as we want
/// to refer to `dyn StorageProvider`.
///
/// See <https://docs.rs/async-trait/latest/async_trait/#dyn-traits>
#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait StorageProvider: RemoteSync + Sync + Send {
    /// Get the event log cache.
    fn cache(&self) -> &HashMap<VaultId, (EventLogFile, PatchFile)>;

    /// Get the mutable event log cache.
    fn cache_mut(
        &mut self,
    ) -> &mut HashMap<VaultId, (EventLogFile, PatchFile)>;

    /// Get the state for this storage provider.
    fn state(&self) -> &ProviderState;

    /// Get a mutable reference to the state for this storage provider.
    fn state_mut(&mut self) -> &mut ProviderState;

    /// Get the audit log for this provider.
    fn audit_log(&self) -> Arc<RwLock<AuditLogFile>>;

    /// Create the search index for the currently open vault.
    async fn create_search_index(&mut self) -> Result<()> {
        self.state_mut().create_search_index().await
    }

    /// Compute the storage directory for the user.
    fn paths(&self) -> &UserPaths;

    /// Import the vaults for a new account.
    async fn import_new_account(
        &mut self,
        account: &NewAccount,
    ) -> Result<(ImportedAccount, Vec<Event<'static>>)> {
        let mut events = Vec::new();

        events.push(Event::CreateAccount(AuditEvent::new(
            EventKind::CreateAccount,
            account.address.clone(),
            None,
        )));

        // Save the default vault
        let buffer = encode(&account.default_vault).await?;

        let (event, summary) =
            self.create_account_from_buffer(buffer).await?;
        events.push(Event::Write(*summary.id(), event.into_owned()));

        let archive = if let Some(archive_vault) = &account.archive {
            let buffer = encode(archive_vault).await?;
            let (event, summary) = self.import_vault(buffer).await?;
            events.push(Event::Write(*summary.id(), event.into_owned()));
            Some(summary)
        } else {
            None
        };

        let authenticator =
            if let Some(authenticator_vault) = &account.authenticator {
                let buffer = encode(authenticator_vault).await?;
                let (event, summary) = self.import_vault(buffer).await?;
                events.push(Event::Write(*summary.id(), event.into_owned()));
                Some(summary)
            } else {
                None
            };

        let contacts = if let Some(contact_vault) = &account.contacts {
            let buffer = encode(contact_vault).await?;
            let (event, summary) = self.import_vault(buffer).await?;
            events.push(Event::Write(*summary.id(), event.into_owned()));
            Some(summary)
        } else {
            None
        };

        Ok((
            ImportedAccount {
                summary,
                archive,
                authenticator,
                contacts,
            },
            events,
        ))
    }

    /// Restore vaults from an archive.
    ///
    /// Buffer is the compressed archive contents.
    async fn restore_archive(
        &mut self,
        targets: &RestoreTargets,
    ) -> Result<()> {
        let RestoreTargets { vaults, .. } = targets;

        // We may be restoring vaults that do not exist
        // so we need to update the cache
        let summaries = vaults
            .iter()
            .map(|(_, v)| v.summary().clone())
            .collect::<Vec<_>>();
        self.load_caches(&summaries).await?;

        for (buffer, vault) in vaults {
            // Prepare a fresh log of event log events
            let mut event_log_events = Vec::new();
            let create_vault = WriteEvent::CreateVault(Cow::Borrowed(buffer));
            event_log_events.push(create_vault);

            self.update_vault(vault.summary(), vault, event_log_events)
                .await?;

            // Refresh the in-memory and disc-based mirror
            self.refresh_vault(vault.summary(), None).await?;
        }

        Ok(())
    }

    /// Initiate noise protocol handshake with a remote server.
    async fn handshake(&mut self) -> Result<()> {
        Ok(())
    }

    /// Get the path to a event log file.
    fn event_log_path(&self, summary: &Summary) -> PathBuf {
        let file_name = format!("{}.{}", summary.id(), EVENT_LOG_EXT);
        self.paths().vaults_dir().join(file_name)
    }

    /// Get the path to a vault file.
    fn vault_path(&self, summary: &Summary) -> PathBuf {
        let file_name = format!("{}.{}", summary.id(), VAULT_EXT);
        self.paths().vaults_dir().join(file_name)
    }

    /// Get the path to a patch file.
    fn patch_path(&self, summary: &Summary) -> PathBuf {
        let file_name = format!("{}.{}", summary.id(), PATCH_EXT);
        self.paths().vaults_dir().join(file_name)
    }

    /// Get the vault summaries for this storage.
    fn vaults(&self) -> &[Summary] {
        self.state().summaries()
    }

    /// Get the current in-memory vault access.
    fn current(&self) -> Option<&Gatekeeper> {
        self.state().current()
    }

    /// Get a mutable reference to the current in-memory vault access.
    fn current_mut(&mut self) -> Option<&mut Gatekeeper> {
        self.state_mut().current_mut()
    }

    /// Update an existing vault by replacing it with a new vault.
    async fn update_vault<'a>(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<WriteEvent<'a>>,
    ) -> Result<()>;

    /// Compact a event log file.
    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)>;

    /// Refresh the in-memory vault of the current selection
    /// from the contents of the current event log file.
    async fn refresh_vault(
        &mut self,
        summary: &Summary,
        new_key: Option<&AccessKey>,
    ) -> Result<()> {
        let vault = self.reduce_event_log(summary).await?;

        // Rewrite the on-disc version if we are mirroring
        if self.state().mirror() {
            let buffer = encode(&vault).await?;
            self.write_vault_file(summary, &buffer).await?;
        }

        if let Some(keeper) = self.current_mut() {
            if keeper.id() == summary.id() {
                // Update the in-memory version
                let new_key = if let Some(new_key) = new_key {
                    if let Some(salt) = vault.salt() {
                        match new_key {
                            AccessKey::Password(password) => {
                                let salt = KeyDerivation::parse_salt(salt)?;
                                let deriver = vault.deriver();
                                let derived_private_key = deriver.derive(
                                    &password,
                                    &salt,
                                    keeper.vault().seed(),
                                )?;
                                Some(PrivateKey::Symmetric(
                                    derived_private_key,
                                ))
                            }
                            AccessKey::Identity(id) => {
                                Some(PrivateKey::Asymmetric(id.clone()))
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                keeper.replace_vault(vault, new_key).await?;
            }
        }
        Ok(())
    }

    /// Get the account status.
    async fn account_status(&mut self) -> Result<AccountStatus>;

    /// Create a new account and default login vault.
    async fn create_account(
        &mut self,
        name: Option<String>,
        key: Option<AccessKey>,
    ) -> Result<(WriteEvent<'static>, AccessKey, Summary)> {
        self.create_vault_or_account(name, key, true).await
    }

    /// Create a new vault.
    async fn create_vault(
        &mut self,
        name: String,
        key: Option<AccessKey>,
    ) -> Result<(WriteEvent<'static>, AccessKey, Summary)> {
        self.create_vault_or_account(Some(name), key, false).await
    }

    /// Import a vault into an existing account.
    async fn import_vault(
        &mut self,
        buffer: Vec<u8>,
    ) -> Result<(WriteEvent<'static>, Summary)>;

    /// Create a new account using the given vault buffer.
    async fn create_account_from_buffer(
        &mut self,
        buffer: Vec<u8>,
    ) -> Result<(WriteEvent<'static>, Summary)>;

    /// Create a new account or vault.
    async fn create_vault_or_account(
        &mut self,
        name: Option<String>,
        key: Option<AccessKey>,
        _is_account: bool,
    ) -> Result<(WriteEvent<'static>, AccessKey, Summary)>;

    /// Remove a vault.
    async fn remove_vault(
        &mut self,
        summary: &Summary,
    ) -> Result<WriteEvent<'static>>;

    /// Load vault summaries from the local disc.
    async fn load_vaults(&mut self) -> Result<&[Summary]> {
        let storage = self.paths().vaults_dir();
        let mut summaries = Vec::new();
        let mut contents = vfs::read_dir(&storage).await?;
        while let Some(entry) = contents.next_entry().await? {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if extension == VAULT_EXT {
                    let summary = Header::read_summary_file(path).await?;
                    if summary.flags().is_system() {
                        continue;
                    }
                    summaries.push(summary);
                }
            }
        }

        self.load_caches(&summaries).await?;
        self.state_mut().set_summaries(summaries);
        Ok(self.vaults())
    }

    //async fn load_vaults(&mut self) -> Result<&[Summary]>;

    /// Attempt to set the vault name for a vault.
    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<WriteEvent<'static>>;

    /// Load a vault, unlock it and set it as the current vault.
    async fn open_vault(
        &mut self,
        summary: &Summary,
        key: AccessKey,
        index: Option<Arc<RwLock<SearchIndex>>>,
    ) -> Result<ReadEvent> {
        let vault_path = self.vault_path(summary);
        let vault = if self.state().mirror() {
            if !vfs::try_exists(&vault_path).await? {
                let vault = self.reduce_event_log(summary).await?;
                let buffer = encode(&vault).await?;
                self.write_vault_file(summary, &buffer).await?;
                vault
            } else {
                let buffer = vfs::read(&vault_path).await?;
                let vault: Vault = decode(&buffer).await?;
                vault
            }
        } else {
            self.reduce_event_log(summary).await?
        };

        self.state_mut()
            .open_vault(key, vault, vault_path, index)
            .await?;
        Ok(ReadEvent::ReadVault)
    }

    /// Load a vault by reducing it from the event log stored on disc.
    ///
    /// Remote providers may pull changes beforehand.
    async fn reduce_event_log(&mut self, summary: &Summary) -> Result<Vault>;

    /// Apply changes to a vault.
    async fn patch(
        &mut self,
        summary: &Summary,
        events: Vec<WriteEvent<'static>>,
    ) -> Result<()>;

    /// Close the currently selected vault.
    fn close_vault(&mut self);

    /// Get a reference to the commit tree for an event log file.
    fn commit_tree(&self, summary: &Summary) -> Option<&CommitTree>;

    /// Create a cache entry for each summary if it does not
    /// already exist.
    async fn load_caches(&mut self, summaries: &[Summary]) -> Result<()> {
        for summary in summaries {
            // Ensure we don't overwrite existing data
            if self.cache().get(summary.id()).is_none() {
                self.create_cache_entry(summary, None).await?;
            }
        }
        Ok(())
    }

    /// Create new patch and event log cache entries.
    async fn create_cache_entry(
        &mut self,
        summary: &Summary,
        vault: Option<Vault>,
    ) -> Result<()> {
        let patch_path = self.patch_path(summary);
        let patch_file = PatchFile::new(patch_path).await?;

        let event_log_path = self.event_log_path(summary);
        let mut event_log = EventLogFile::new(&event_log_path).await?;

        if let Some(vault) = &vault {
            let encoded = encode(vault).await?;
            let event = WriteEvent::CreateVault(Cow::Owned(encoded));
            event_log.append_event(event).await?;
        }
        event_log.load_tree().await?;

        self.cache_mut()
            .insert(*summary.id(), (event_log, patch_file));
        Ok(())
    }

    /// Add to the local cache for a vault.
    async fn add_local_cache(&mut self, summary: Summary) -> Result<()> {
        // Add to our cache of managed vaults
        self.create_cache_entry(&summary, None).await?;

        // Add to the state of managed vaults
        self.state_mut().add_summary(summary);
        Ok(())
    }

    /// Remove the local cache for a vault.
    fn remove_local_cache(&mut self, summary: &Summary) -> Result<()>;

    //fn load_caches(&mut self, summaries: &[Summary]) -> Result<()>;

    /// Respond to a change notification.
    ///
    /// The return flag indicates whether the change was made
    /// by this node which is determined by comparing the session
    /// identifier on the change notification with the current
    /// session identifier for this node.
    async fn handle_change(
        &mut self,
        change: ChangeNotification,
    ) -> Result<(bool, HashSet<ChangeAction>)>;

    /// Download changes from a remote server.
    ///
    /// For a local provider this is a noop.
    async fn pull(
        &mut self,
        summary: &Summary,
        _force: bool,
    ) -> Result<SyncInfo>;

    /// Upload changes to a remote server.
    ///
    /// For a local provider this is a noop.
    async fn push(
        &mut self,
        summary: &Summary,
        _force: bool,
    ) -> Result<SyncInfo>;

    /// Get a comparison between a local and remote.
    ///
    /// If a patch file has unsaved events then the number
    /// of pending events is returned along with the `CommitRelationship`.
    ///
    /// For a local provider this will always return an equal status.
    async fn status(
        &mut self,
        summary: &Summary,
    ) -> Result<(CommitRelationship, Option<usize>)>;

    /// Remove a vault file and event log file.
    async fn remove_vault_file(&self, summary: &Summary) -> Result<()> {
        use sos_sdk::constants::EVENT_LOG_DELETED_EXT;

        // Remove local vault mirror if it exists
        let vault_path = self.vault_path(summary);
        if vfs::try_exists(&vault_path).await? {
            vfs::remove_file(&vault_path).await?;
        }

        // Rename the local event log file so recovery is still possible
        let event_log_path = self.event_log_path(summary);
        if vfs::try_exists(&event_log_path).await? {
            let mut event_log_path_backup = event_log_path.clone();
            event_log_path_backup.set_extension(EVENT_LOG_DELETED_EXT);
            vfs::rename(event_log_path, event_log_path_backup).await?;
        }
        Ok(())
    }

    /// Create a backup of a vault file.
    async fn backup_vault_file(&self, summary: &Summary) -> Result<()> {
        use sos_sdk::constants::VAULT_BACKUP_EXT;

        // Move our cached vault to a backup
        let vault_path = self.vault_path(summary);

        if vfs::try_exists(&vault_path).await? {
            let mut vault_backup = vault_path.clone();
            vault_backup.set_extension(VAULT_BACKUP_EXT);
            vfs::rename(&vault_path, &vault_backup).await?;
            tracing::debug!(
                vault = ?vault_path, backup = ?vault_backup, "vault backup");
        }

        Ok(())
    }

    /// Write the buffer for a vault to disc.
    async fn write_vault_file(
        &self,
        summary: &Summary,
        buffer: &[u8],
    ) -> Result<()> {
        let vault_path = self.vault_path(&summary);
        vfs::write(vault_path, buffer).await?;
        Ok(())
    }

    /// Create a secret in the currently open vault.
    async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
    ) -> Result<WriteEvent<'_>> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        let event = keeper.create(meta, secret).await?.into_owned();
        self.patch(&summary, vec![event.clone()]).await?;
        Ok(event)
    }

    /// Read a secret in the currently open vault.
    async fn read_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, ReadEvent)> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let _summary = keeper.summary().clone();
        let result =
            keeper.read(id).await?.ok_or(Error::SecretNotFound(*id))?;
        Ok(result)
    }

    /// Update a secret in the currently open vault.
    async fn update_secret(
        &mut self,
        id: &SecretId,
        mut secret_data: SecretData,
    ) -> Result<WriteEvent<'_>> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        secret_data.meta.touch();
        let event = keeper
            .update(id, secret_data.meta, secret_data.secret)
            .await?
            .ok_or(Error::SecretNotFound(*id))?;
        let event = event.into_owned();
        self.patch(&summary, vec![event.clone()]).await?;
        Ok(event)
    }

    /// Delete a secret in the currently open vault.
    async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<WriteEvent<'_>> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        let event =
            keeper.delete(id).await?.ok_or(Error::SecretNotFound(*id))?;
        let event = event.into_owned();
        self.patch(&summary, vec![event.clone()]).await?;
        Ok(event)
    }

    /// Change the password for a vault.
    ///
    /// If the target vault is the currently selected vault
    /// the currently selected vault is unlocked with the new
    /// passphrase on success.
    async fn change_password(
        &mut self,
        vault: &Vault,
        current_key: AccessKey,
        new_key: AccessKey,
    ) -> Result<AccessKey> {
        let (new_key, new_vault, event_log_events) =
            ChangePassword::new(vault, current_key, new_key, None)
                .build()
                .await?;

        self.update_vault(vault.summary(), &new_vault, event_log_events)
            .await?;

        // Refresh the in-memory and disc-based mirror
        self.refresh_vault(vault.summary(), Some(&new_key)).await?;

        if let Some(keeper) = self.current_mut() {
            if keeper.summary().id() == vault.summary().id() {
                keeper.unlock(new_key.clone()).await?;
            }
        }

        Ok(new_key)
    }

    /// Verify a event log log.
    async fn verify(&self, summary: &Summary) -> Result<()> {
        use sos_sdk::commit::event_log_commit_tree_file;
        let event_log_path = self.event_log_path(summary);
        event_log_commit_tree_file(&event_log_path, true, |_| {}).await?;
        Ok(())
    }

    /// Get the history of events for a vault.
    async fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(CommitHash, Timestamp, WriteEvent<'_>)>> {
        let (event_log, _) = self
            .cache()
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let mut records = Vec::new();
        let mut it = event_log.iter().await?;
        while let Some(record) = it.next_entry().await? {
            let event = event_log.event_data(&record).await?;
            let commit = CommitHash(record.commit());
            let time = record.time().clone();
            records.push((commit, time, event));
        }
        Ok(records)
    }
}

/// Shared provider implementation.
#[doc(hidden)]
#[macro_export]
macro_rules! provider_impl {
    () => {
        fn cache(&self) -> &HashMap<VaultId, (EventLogFile, PatchFile)> {
            &self.cache
        }

        fn cache_mut(
            &mut self,
        ) -> &mut HashMap<VaultId, (EventLogFile, PatchFile)> {
            &mut self.cache
        }

        fn state(&self) -> &ProviderState {
            &self.state
        }

        fn state_mut(&mut self) -> &mut ProviderState {
            &mut self.state
        }

        fn audit_log(&self) -> Arc<RwLock<AuditLogFile>> {
            Arc::clone(&self.audit_log)
        }

        fn paths(&self) -> &UserPaths {
            &self.paths
        }

        fn close_vault(&mut self) {
            self.state_mut().close_vault();
        }

        fn commit_tree(&self, summary: &Summary) -> Option<&CommitTree> {
            self.cache
                .get(summary.id())
                .map(|(event_log, _)| event_log.tree())
        }

        fn remove_local_cache(&mut self, summary: &Summary) -> Result<()> {
            let current_id = self.current().map(|c| c.id().clone());

            // If the deleted vault is the currently selected
            // vault we must close it
            if let Some(id) = &current_id {
                if id == summary.id() {
                    self.close_vault();
                }
            }

            // Remove from our cache of managed vaults
            self.cache.remove(summary.id());

            // Remove from the state of managed vaults
            self.state_mut().remove_summary(summary);

            Ok(())
        }
    };
}
