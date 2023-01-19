//! Storage provider trait.

use async_trait::async_trait;
use parking_lot::RwLock;
use secrecy::{ExposeSecret, SecretString};
use std::{
    borrow::Cow,
    collections::HashSet,
    io::Cursor,
    path::{Path, PathBuf},
    sync::Arc,
};

use sos_core::{
    archive::{inflate, ArchiveItem, Reader},
    commit_tree::{CommitProof, CommitTree},
    constants::{LOCAL_DIR, PATCH_EXT, VAULTS_DIR, VAULT_EXT, WAL_EXT},
    decode,
    events::{ChangeAction, ChangeNotification, SyncEvent, WalEvent},
    identity::Identity,
    search::SearchIndex,
    secret::{Secret, SecretId, SecretMeta},
    vault::{Summary, Vault},
    wal::snapshot::{SnapShot, SnapShotManager},
    ChangePassword, CommitHash, Gatekeeper, Timestamp,
};

use crate::{
    client::{Error, Result},
    sync::{SyncInfo, SyncStatus},
};

pub(crate) fn assert_proofs_eq(
    client_proof: &CommitProof,
    server_proof: &CommitProof,
) -> Result<()> {
    if client_proof.0 != server_proof.0 {
        let client = CommitHash(client_proof.0);
        let server = CommitHash(server_proof.0);
        Err(Error::RootHashMismatch(client, server))
    } else {
        Ok(())
    }
}

mod fs_adapter;

#[cfg(not(target_arch = "wasm32"))]
mod local_provider;
mod macros;
#[cfg(target_arch = "wasm32")]
mod memory_provider;
mod provider_factory;
mod remote_provider;
mod state;
mod sync;

#[cfg(not(target_arch = "wasm32"))]
pub use local_provider::LocalProvider;
#[cfg(not(target_arch = "wasm32"))]
pub use provider_factory::spawn_changes_listener;
pub use provider_factory::{ArcProvider, ProviderFactory};
pub use remote_provider::RemoteProvider;

#[cfg(target_arch = "wasm32")]
pub use memory_provider::MemoryProvider;

pub use state::ProviderState;

/// Generic boxed provider.
pub type BoxedProvider = Box<dyn StorageProvider + Send + Sync + 'static>;

/// Encapsulates the paths for vault storage.
#[derive(Default, Debug)]
pub struct StorageDirs {
    /// Top-level documents folder.
    documents_dir: PathBuf,
    /// User segregated storage.
    user_dir: PathBuf,
    /// Sub-directory for the vaults.
    vaults_dir: PathBuf,
}

impl StorageDirs {
    /// Create new storage dirs.
    pub fn new<D: AsRef<Path>>(documents_dir: D, user_id: &str) -> Self {
        let documents_dir = documents_dir.as_ref().to_path_buf();
        let local_dir = documents_dir.join(LOCAL_DIR);
        let user_dir = local_dir.join(user_id);
        let vaults_dir = user_dir.join(VAULTS_DIR);
        Self {
            documents_dir,
            user_dir,
            vaults_dir,
        }
    }

    /// Ensure all the directories exist.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.vaults_dir)?;
        Ok(())
    }

    /// Get the documents storage directory.
    pub fn documents_dir(&self) -> &PathBuf {
        &self.documents_dir
    }

    /// Get the user storage directory.
    pub fn user_dir(&self) -> &PathBuf {
        &self.user_dir
    }

    /// Get the vaults storage directory.
    pub fn vaults_dir(&self) -> &PathBuf {
        &self.vaults_dir
    }
}

/// Options for a restore operation.
pub struct RestoreOptions {
    /// Whether to overwrite an existing identity vault.
    pub overwrite_identity: bool,
    /// Vaults that the user selected to be imported.
    pub selected: Vec<Summary>,
    /// Passphrase to verify the vaults can be decrypted before import.
    pub passphrase: Option<SecretString>,
}

/// Buffers of data to restore after selected options
/// have been applied to the data in an archive.
pub struct RestoreTargets {
    /// The address for the identity.
    pub address: String,
    /// Archive item for the identity vault.
    pub identity: ArchiveItem,
    /// List of vaults to restore.
    pub vaults: Vec<(Vec<u8>, Vault)>,
}

/// Trait for storage providers.
///
/// Note we need `Sync` and `Send` super traits as we want
/// to refer to `dyn StorageProvider`.
///
/// See: https://docs.rs/async-trait/latest/async_trait/#dyn-traits
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

    /// Get the snapshot manager for this cache.
    fn snapshots(&self) -> Option<&SnapShotManager>;

    /// Take a snapshot of the WAL for the given vault.
    ///
    /// Snapshots must be enabled.
    fn take_snapshot(&self, summary: &Summary) -> Result<(SnapShot, bool)>;

    /// Restore vaults from an archive.
    ///
    /// Buffer is the compressed archive contents.
    async fn restore_archive(
        &mut self,
        buffer: Vec<u8>,
        options: RestoreOptions,
    ) -> Result<(String, ArchiveItem)> {
        let RestoreTargets {
            address,
            identity,
            vaults,
        } = self.extract_verify_archive(buffer, &options)?;

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
            let create_vault = WalEvent::CreateVault(Cow::Owned(buffer));
            wal_events.push(create_vault);

            self.update_vault(vault.summary(), &vault, wal_events)
                .await?;

            // Refresh the in-memory and disc-based mirror
            self.refresh_vault(vault.summary(), None)?;
        }

        Ok((address, identity))
    }

    /// Helper to extract from an archive and verify the archive
    /// contents against the restore options.
    fn extract_verify_archive(
        &self,
        buffer: Vec<u8>,
        options: &RestoreOptions,
    ) -> Result<RestoreTargets> {
        // Decompress
        let mut archive = Vec::new();
        inflate(buffer.as_slice(), &mut archive)?;

        // Read from the tarball
        let reader = Reader::new(Cursor::new(archive));
        let (address, identity, vaults) = reader.prepare()?.finish()?;

        // Filter extracted vaults to those selected by the user
        let vaults = vaults
            .into_iter()
            .filter(|item| {
                options
                    .selected
                    .iter()
                    .find(|s| s.id() == item.0.id())
                    .is_some()
            })
            .collect::<Vec<_>>();

        let default_vault =
            vaults.iter().find(|item| item.0.flags().is_default());
        if default_vault.is_none() {
            return Err(Error::NoArchiveDefaultVault);
        }

        // Check each target vault can be decoded
        let mut decoded: Vec<(Vec<u8>, Vault)> = Vec::new();
        for item in vaults {
            let vault: Vault = decode(&item.1)?;
            decoded.push((item.1, vault));
        }

        // Check all the decoded vaults can be decrypted
        if let Some(passphrase) = &options.passphrase {
            // Check the identity vault
            let vault: Vault = decode(&identity.1)?;
            let mut keeper = Gatekeeper::new(vault, None);
            keeper.unlock(passphrase.expose_secret())?;

            for (_, vault) in &decoded {
                let mut keeper = Gatekeeper::new(vault.clone(), None);
                keeper.unlock(passphrase.expose_secret())?;
            }

            // Get the signing address from the identity vault and
            // verify it matches the manifest address
            let (user, _) =
                Identity::login_buffer(&identity.1, passphrase.clone())?;
            if user.signer.address()?.to_string() != address {
                return Err(Error::ArchiveAddressMismatch);
            }
        }

        Ok(RestoreTargets {
            address,
            identity,
            vaults: decoded,
        })
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
        self.dirs().vaults_dir().join(&file_name)
    }

    /// Get the path to a vault file.
    fn vault_path(&self, summary: &Summary) -> PathBuf {
        let file_name = format!("{}.{}", summary.id(), VAULT_EXT);
        self.dirs().vaults_dir().join(&file_name)
    }

    /// Get the path to a patch file.
    fn patch_path(&self, summary: &Summary) -> PathBuf {
        let file_name = format!("{}.{}", summary.id(), PATCH_EXT);
        self.dirs().vaults_dir().join(&file_name)
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
    ) -> Result<Vec<(CommitHash, Timestamp, WalEvent<'_>)>>;

    /// Update an existing vault by replacing it with a new vault.
    async fn update_vault<'a>(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<WalEvent<'a>>,
    ) -> Result<()>;

    /// Compact a WAL file.
    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)>;

    /// Refresh the in-memory vault of the current selection
    /// from the contents of the current WAL file.
    fn refresh_vault(
        &mut self,
        summary: &Summary,
        new_passphrase: Option<&SecretString>,
    ) -> Result<()>;

    /// Create a new account and default login vault.
    async fn create_account(
        &mut self,
        name: Option<String>,
        passphrase: Option<String>,
    ) -> Result<(SecretString, Summary)> {
        self.create_vault_or_account(name, passphrase, true).await
    }

    /// Create a new vault.
    async fn create_vault(
        &mut self,
        name: String,
        passphrase: Option<String>,
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
        passphrase: Option<String>,
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
    fn open_vault(
        &mut self,
        summary: &Summary,
        passphrase: &str,
        index: Option<Arc<RwLock<SearchIndex>>>,
    ) -> Result<()>;

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
    /// of pending events is returned along with the `SyncStatus`.
    ///
    /// For a local provider this will always return an equal status.
    async fn status(
        &mut self,
        summary: &Summary,
    ) -> Result<(SyncStatus, Option<usize>)>;

    /// Verify a WAL log.
    fn verify(&self, summary: &Summary) -> Result<()>;

    /// Create a backup of a vault file.
    fn backup_vault_file(&self, summary: &Summary) -> Result<()>;

    /// Remove a vault file and WAL file.
    fn remove_vault_file(&self, summary: &Summary) -> Result<()>;

    /// Write the buffer for a vault to disc.
    fn write_vault_file(
        &self,
        summary: &Summary,
        buffer: &[u8],
    ) -> Result<()>;

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
        mut meta: SecretMeta,
        secret: Secret,
    ) -> Result<SyncEvent<'_>> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        meta.touch();
        let event = keeper
            .update(id, meta, secret)?
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
        let (new_passphrase, new_vault, wal_events) =
            ChangePassword::new(vault, current_passphrase, new_passphrase)
                .build()?;

        self.update_vault(vault.summary(), &new_vault, wal_events)
            .await?;

        // Refresh the in-memory and disc-based mirror
        self.refresh_vault(vault.summary(), Some(&new_passphrase))?;

        if let Some(keeper) = self.current_mut() {
            if keeper.summary().id() == vault.summary().id() {
                keeper.unlock(new_passphrase.expose_secret())?;
            }
        }

        Ok(new_passphrase)
    }
}

/// Shared provider implementation.
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

        fn snapshots(&self) -> Option<&SnapShotManager> {
            self.snapshots.as_ref()
        }

        fn open_vault(
            &mut self,
            summary: &Summary,
            passphrase: &str,
            index: Option<std::sync::Arc<parking_lot::RwLock<SearchIndex>>>,
        ) -> Result<()> {
            let vault_path = self.vault_path(summary);
            let vault = if self.state().mirror() {
                if !vault_path.exists() {
                    let vault = self.reduce_wal(summary)?;
                    let buffer = encode(&vault)?;
                    self.write_vault_file(summary, &buffer)?;
                    vault
                } else {
                    let buffer = std::fs::read(&vault_path)?;
                    let vault: Vault = decode(&buffer)?;
                    vault
                }
            } else {
                self.reduce_wal(summary)?
            };

            self
                .state_mut()
                .open_vault(passphrase, vault, vault_path, index)?;
            Ok(())
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
            let patch_file = P::new(patch_path)?;

            let wal_path = self.wal_path(summary);
            let mut wal = W::new(&wal_path)?;

            if let Some(vault) = &vault {
                let encoded = encode(vault)?;
                let event = WalEvent::CreateVault(Cow::Owned(encoded));
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

        #[cfg(not(target_arch = "wasm32"))]
        fn verify(&self, summary: &Summary) -> Result<()> {
            use sos_core::commit_tree::wal_commit_tree_file;
            let wal_path = self.wal_path(summary);
            wal_commit_tree_file(&wal_path, true, |_| {})?;
            Ok(())
        }

        #[cfg(target_arch = "wasm32")]
        fn verify(&self, _summary: &Summary) -> Result<()> {
            // NOTE: verify is a noop in WASM when the records
            // NOTE: are stored in memory
            Ok(())
        }

        fn history(&self, summary: &Summary) -> Result<Vec<(CommitHash, Timestamp, WalEvent<'_>)>> {
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

        fn take_snapshot(
            &self,
            summary: &Summary,
        ) -> Result<(SnapShot, bool)> {
            let snapshots =
                self.snapshots().ok_or(Error::SnapshotsNotEnabled)?;
            let (wal_file, _) = self
                .cache
                .get(summary.id())
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            let root_hash =
                wal_file.tree().root().ok_or(Error::NoRootCommit)?;
            Ok(snapshots.create(summary.id(), wal_file.path(), root_hash)?)
        }

        /// Refresh the in-memory vault of the current selection
        /// from the contents of the current WAL file.
        fn refresh_vault(
            &mut self,
            summary: &Summary,
            new_passphrase: Option<&SecretString>,
        ) -> Result<()> {
            let wal = self
                .cache
                .get_mut(summary.id())
                .map(|(w, _)| w)
                .ok_or(Error::CacheNotAvailable(*summary.id()))?;
            let vault = WalReducer::new().reduce(wal)?.build()?;

            // Rewrite the on-disc version if we are mirroring
            if self.state().mirror() {
                let buffer = encode(&vault)?;
                self.write_vault_file(summary, &buffer)?;
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


        /// Write the buffer for a vault to disc.
        #[cfg(not(target_arch = "wasm32"))]
        fn write_vault_file(
            &self,
            summary: &Summary,
            buffer: &[u8],
        ) -> Result<()> {
            use crate::client::provider::fs_adapter;
            let vault_path = self.vault_path(&summary);
            fs_adapter::write(vault_path, buffer)?;
            Ok(())
        }

        /// Write the buffer for a vault to disc.
        #[cfg(target_arch = "wasm32")]
        fn write_vault_file(
            &self,
            _summary: &Summary,
            _buffer: &[u8],
        ) -> Result<()> {
            Ok(())
        }


        /// Create a backup of a vault file.
        #[cfg(not(target_arch = "wasm32"))]
        fn backup_vault_file(&self, summary: &Summary) -> Result<()> {
            use sos_core::constants::VAULT_BACKUP_EXT;

            // Move our cached vault to a backup
            let vault_path = self.vault_path(summary);

            if vault_path.exists() {
                let mut vault_backup = vault_path.clone();
                vault_backup.set_extension(VAULT_BACKUP_EXT);
                fs_adapter::rename(&vault_path, &vault_backup)?;
                tracing::debug!(
                    vault = ?vault_path, backup = ?vault_backup, "vault backup");
            }

            Ok(())
        }

        /// Create a backup of a vault file.
        #[cfg(target_arch = "wasm32")]
        fn backup_vault_file(&self, _summary: &Summary) -> Result<()> {
            Ok(())
        }

        /// Remove a vault file and WAL file.
        #[cfg(not(target_arch = "wasm32"))]
        fn remove_vault_file(&self, summary: &Summary) -> Result<()> {
            use sos_core::constants::WAL_DELETED_EXT;

            // Remove local vault mirror if it exists
            let vault_path = self.vault_path(summary);
            if vault_path.exists() {
                fs_adapter::remove_file(&vault_path)?;
            }

            // Rename the local WAL file so recovery is still possible
            let wal_path = self.wal_path(summary);
            if wal_path.exists() {
                let mut wal_path_backup = wal_path.clone();
                wal_path_backup.set_extension(WAL_DELETED_EXT);
                fs_adapter::rename(wal_path, wal_path_backup)?;
            }
            Ok(())
        }

        /// Remove a vault file and WAL file.
        #[cfg(target_arch = "wasm32")]
        fn remove_vault_file(&self, _summary: &Summary) -> Result<()> {
            Ok(())
        }
    };
}
