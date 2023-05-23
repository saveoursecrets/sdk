//! Storage provider trait.

use async_trait::async_trait;

use secrecy::SecretString;
use std::{borrow::Cow, collections::HashSet, path::PathBuf};

use sos_sdk::{
    account::{ImportedAccount, NewAccount},
    commit::{
        CommitHash, CommitProof, CommitRelationship, CommitTree, SyncInfo,
    },
    constants::{PATCH_EXT, VAULT_EXT, WAL_EXT},
    crypto::secret_key::SecretKey,
    decode, encode,
    events::{ChangeAction, ChangeNotification, SyncEvent},
    passwd::ChangePassword,
    search::SearchIndex,
    storage::StorageDirs,
    vault::{
        secret::{Secret, SecretData, SecretId, SecretMeta},
        Gatekeeper, Summary, Vault,
    },
    vfs, Timestamp,
};

use secrecy::ExposeSecret;

use sos_sdk::account::RestoreTargets;

use crate::client::{Error, Result};

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
pub use provider_factory::{ArcProvider, ProviderFactory};
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
pub trait StorageProvider: Sync + Send {
    /// Get the state for this storage provider.
    fn state(&self) -> &ProviderState;

    /// Get a mutable reference to the state for this storage provider.
    fn state_mut(&mut self) -> &mut ProviderState;

    /// Create the search index for the currently open vault.
    fn create_search_index(&mut self) -> Result<()> {
        self.state_mut().create_search_index()
    }

    /// Compute the storage directory for the user.
    fn dirs(&self) -> &StorageDirs;

    /// Import the vaults for a new account.
    async fn import_new_account(
        &mut self,
        account: &NewAccount,
    ) -> Result<ImportedAccount> {
        // Save the default vault
        let buffer = encode(&account.default_vault)?;
        let summary = self.create_account_with_buffer(buffer).await?;

        let archive = if let Some(archive_vault) = &account.archive {
            let buffer = encode(archive_vault)?;
            let summary = self.import_vault(buffer).await?;
            Some(summary)
        } else {
            None
        };

        let authenticator =
            if let Some(authenticator_vault) = &account.authenticator {
                let buffer = encode(authenticator_vault)?;
                let summary = self.import_vault(buffer).await?;
                Some(summary)
            } else {
                None
            };

        let contacts = if let Some(contact_vault) = &account.contacts {
            let buffer = encode(contact_vault)?;
            let summary = self.import_vault(buffer).await?;
            Some(summary)
        } else {
            None
        };

        Ok(ImportedAccount {
            summary,
            archive,
            authenticator,
            contacts,
        })
    }

    /// Restore vaults from an archive.
    ///
    /// Buffer is the compressed archive contents.
    #[cfg(not(target_arch = "wasm32"))]
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
        self.load_caches(&summaries)?;

        for (buffer, vault) in vaults {
            // Prepare a fresh log of WAL events
            let mut wal_events = Vec::new();
            let create_vault = SyncEvent::CreateVault(Cow::Borrowed(buffer));
            wal_events.push(create_vault);

            self.update_vault(vault.summary(), vault, wal_events)
                .await?;

            // Refresh the in-memory and disc-based mirror
            self.refresh_vault(vault.summary(), None).await?;
        }

        Ok(())
    }

    /// Attempt to open an authenticated, encrypted session.
    ///
    /// Must be called before using any other methods that
    /// communicate over the network to prepare the client session.
    ///
    /// For a local provider this is a noop.
    async fn authenticate(&mut self) -> Result<()> {
        Ok(())
    }

    /// Get the path to a WAL file.
    fn wal_path(&self, summary: &Summary) -> PathBuf {
        let file_name = format!("{}.{}", summary.id(), WAL_EXT);
        self.dirs().vaults_dir().join(file_name)
    }

    /// Get the path to a vault file.
    fn vault_path(&self, summary: &Summary) -> PathBuf {
        let file_name = format!("{}.{}", summary.id(), VAULT_EXT);
        self.dirs().vaults_dir().join(file_name)
    }

    /// Get the path to a patch file.
    fn patch_path(&self, summary: &Summary) -> PathBuf {
        let file_name = format!("{}.{}", summary.id(), PATCH_EXT);
        self.dirs().vaults_dir().join(file_name)
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

    /// Get the history of events for a vault.
    fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(CommitHash, Timestamp, SyncEvent<'_>)>>;

    /// Update an existing vault by replacing it with a new vault.
    async fn update_vault<'a>(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<SyncEvent<'a>>,
    ) -> Result<()>;

    /// Compact a WAL file.
    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)>;

    /// Refresh the in-memory vault of the current selection
    /// from the contents of the current WAL file.
    async fn refresh_vault(
        &mut self,
        summary: &Summary,
        new_passphrase: Option<&SecretString>,
    ) -> Result<()> {
        let vault = self.reduce_wal(summary)?;

        // Rewrite the on-disc version if we are mirroring
        if self.state().mirror() {
            let buffer = encode(&vault)?;
            self.write_vault_file(summary, &buffer).await?;
        }

        if let Some(keeper) = self.current_mut() {
            if keeper.id() == summary.id() {
                // Update the in-memory version
                let new_key = if let Some(new_passphrase) = new_passphrase {
                    if let Some(salt) = vault.salt() {
                        let salt = SecretKey::parse_salt(salt)?;
                        let private_key = SecretKey::derive_32(
                            new_passphrase.expose_secret(),
                            &salt,
                            keeper.vault().seed(),
                        )?;
                        Some(private_key)
                    } else {
                        None
                    }
                } else {
                    None
                };

                keeper.replace_vault(vault, new_key)?;
            }
        }
        Ok(())
    }

    /// Create a new account and default login vault.
    async fn create_account(
        &mut self,
        name: Option<String>,
        passphrase: Option<SecretString>,
    ) -> Result<(SecretString, Summary)> {
        self.create_vault_or_account(name, passphrase, true).await
    }

    /// Create a new vault.
    async fn create_vault(
        &mut self,
        name: String,
        passphrase: Option<SecretString>,
    ) -> Result<(SecretString, Summary)> {
        self.create_vault_or_account(Some(name), passphrase, false)
            .await
    }

    /// Import a vault into an existing account.
    async fn import_vault(&mut self, buffer: Vec<u8>) -> Result<Summary>;

    /// Create a new account using the given vault buffer.
    async fn create_account_with_buffer(
        &mut self,
        buffer: Vec<u8>,
    ) -> Result<Summary>;

    /// Create a new account or vault.
    async fn create_vault_or_account(
        &mut self,
        name: Option<String>,
        passphrase: Option<SecretString>,
        _is_account: bool,
    ) -> Result<(SecretString, Summary)>;

    /// Remove a vault.
    async fn remove_vault(&mut self, summary: &Summary) -> Result<()>;

    /// Load vault summaries.
    async fn load_vaults(&mut self) -> Result<&[Summary]>;

    /// Attempt to set the vault name for a vault.
    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<()>;

    /// Load a vault, unlock it and set it as the current vault.
    async fn open_vault(
        &mut self,
        summary: &Summary,
        passphrase: SecretString,
        index: Option<std::sync::Arc<parking_lot::RwLock<SearchIndex>>>,
    ) -> Result<()> {
        let vault_path = self.vault_path(summary);
        let vault = if self.state().mirror() {
            if !vault_path.exists() {
                let vault = self.reduce_wal(summary)?;
                let buffer = encode(&vault)?;
                self.write_vault_file(summary, &buffer).await?;
                vault
            } else {
                let buffer = vfs::read(&vault_path).await?;
                let vault: Vault = decode(&buffer)?;
                vault
            }
        } else {
            self.reduce_wal(summary)?
        };

        self.state_mut()
            .open_vault(passphrase, vault, vault_path, index)?;
        Ok(())
    }

    /// Load a vault by reducing it from the WAL stored on disc.
    ///
    /// Remote providers may pull changes beforehand.
    fn reduce_wal(&mut self, summary: &Summary) -> Result<Vault>;

    /// Apply changes to a vault.
    async fn patch(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'static>>,
    ) -> Result<()>;

    /// Close the currently selected vault.
    fn close_vault(&mut self);

    /// Get a reference to the commit tree for a WAL file.
    fn commit_tree(&self, summary: &Summary) -> Option<&CommitTree>;

    /// Create new patch and WAL cache entries.
    fn create_cache_entry(
        &mut self,
        summary: &Summary,
        vault: Option<Vault>,
    ) -> Result<()>;

    /// Remove the local cache for a vault.
    fn remove_local_cache(&mut self, summary: &Summary) -> Result<()>;

    /// Add to the local cache for a vault.
    fn add_local_cache(&mut self, summary: Summary) -> Result<()>;

    /// Create a cache entry for each summary if it does not
    /// already exist.
    fn load_caches(&mut self, summaries: &[Summary]) -> Result<()>;

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

    /// Remove a vault file and WAL file.
    async fn remove_vault_file(&self, summary: &Summary) -> Result<()> {
        use sos_sdk::constants::WAL_DELETED_EXT;

        // Remove local vault mirror if it exists
        let vault_path = self.vault_path(summary);
        if vault_path.exists() {
            vfs::remove_file(&vault_path).await?;
        }

        // Rename the local WAL file so recovery is still possible
        let wal_path = self.wal_path(summary);
        if wal_path.exists() {
            let mut wal_path_backup = wal_path.clone();
            wal_path_backup.set_extension(WAL_DELETED_EXT);
            vfs::rename(wal_path, wal_path_backup).await?;
        }
        Ok(())
    }

    /// Create a backup of a vault file.
    async fn backup_vault_file(&self, summary: &Summary) -> Result<()> {
        use sos_sdk::constants::VAULT_BACKUP_EXT;

        // Move our cached vault to a backup
        let vault_path = self.vault_path(summary);

        if vault_path.exists() {
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
    ) -> Result<SyncEvent<'_>> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        let event = keeper.create(meta, secret)?.into_owned();
        self.patch(&summary, vec![event.clone()]).await?;
        Ok(event)
    }

    /// Read a secret in the currently open vault.
    async fn read_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, SyncEvent<'_>)> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let _summary = keeper.summary().clone();
        let result = keeper.read(id)?.ok_or(Error::SecretNotFound(*id))?;
        Ok(result)
    }

    /// Update a secret in the currently open vault.
    async fn update_secret(
        &mut self,
        id: &SecretId,
        mut secret_data: SecretData,
        //mut meta: SecretMeta,
        //secret: Secret,
    ) -> Result<SyncEvent<'_>> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        secret_data.meta.touch();
        let event = keeper
            .update(id, secret_data.meta, secret_data.secret)?
            .ok_or(Error::SecretNotFound(*id))?;
        let event = event.into_owned();
        self.patch(&summary, vec![event.clone()]).await?;
        Ok(event)
    }

    /// Delete a secret in the currently open vault.
    async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<SyncEvent<'_>> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        let event = keeper.delete(id)?.ok_or(Error::SecretNotFound(*id))?;
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
        current_passphrase: SecretString,
        new_passphrase: SecretString,
    ) -> Result<SecretString> {
        let (new_passphrase, new_vault, wal_events) = ChangePassword::new(
            vault,
            current_passphrase,
            new_passphrase,
            None,
        )
        .build()?;

        self.update_vault(vault.summary(), &new_vault, wal_events)
            .await?;

        // Refresh the in-memory and disc-based mirror
        self.refresh_vault(vault.summary(), Some(&new_passphrase))
            .await?;

        if let Some(keeper) = self.current_mut() {
            if keeper.summary().id() == vault.summary().id() {
                keeper.unlock(new_passphrase.clone())?;
            }
        }

        Ok(new_passphrase)
    }

    /// Verify a WAL log.
    async fn verify(&self, summary: &Summary) -> Result<()> {
        use sos_sdk::commit::wal_commit_tree_file;
        let wal_path = self.wal_path(summary);
        wal_commit_tree_file(&wal_path, true, |_| {}).await?;
        Ok(())
    }
}

/// Shared provider implementation.
#[doc(hidden)]
#[macro_export]
macro_rules! provider_impl {
    () => {
        fn state(&self) -> &ProviderState {
            &self.state
        }

        fn state_mut(&mut self) -> &mut ProviderState {
            &mut self.state
        }

        fn dirs(&self) -> &StorageDirs {
            &self.dirs
        }

        fn close_vault(&mut self) {
            self.state_mut().close_vault();
        }

        fn commit_tree(&self, summary: &Summary) -> Option<&CommitTree> {
            self.cache.get(summary.id()).map(|(wal, _)| wal.tree())
        }

        fn create_cache_entry(
            &mut self,
            summary: &Summary,
            vault: Option<Vault>,
        ) -> Result<()> {
            let patch_path = self.patch_path(summary);
            let patch_file = PatchFile::new(patch_path)?;

            let wal_path = self.wal_path(summary);
            let mut wal = WalFile::new(&wal_path)?;

            if let Some(vault) = &vault {
                let encoded = encode(vault)?;
                let event = SyncEvent::CreateVault(Cow::Owned(encoded));
                wal.append_event(event)?;
            }
            wal.load_tree()?;

            self.cache.insert(*summary.id(), (wal, patch_file));
            Ok(())
        }

        fn add_local_cache(&mut self, summary: Summary) -> Result<()> {
            // Add to our cache of managed vaults
            self.create_cache_entry(&summary, None)?;

            // Add to the state of managed vaults
            self.state_mut().add_summary(summary);
            Ok(())
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

        fn load_caches(&mut self, summaries: &[Summary]) -> Result<()> {
            for summary in summaries {
                // Ensure we don't overwrite existing data
                if self.cache.get(summary.id()).is_none() {
                    self.create_cache_entry(summary, None)?;
                }
            }
            Ok(())
        }

        fn history(
            &self,
            summary: &Summary,
        ) -> Result<Vec<(CommitHash, Timestamp, SyncEvent<'_>)>> {
            let (wal, _) = self
                .cache
                .get(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            let mut records = Vec::new();
            for record in wal.iter()? {
                let record = record?;
                let event = wal.event_data(&record)?;
                let commit = CommitHash(record.commit());
                let time = record.time().clone();
                records.push((commit, time, event));
            }
            Ok(records)
        }
    };
}
