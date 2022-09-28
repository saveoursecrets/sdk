//! Storage provider trait.

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

use sos_core::{
    commit_tree::{CommitPair, CommitProof, CommitTree},
    constants::{PATCH_EXT, VAULTS_DIR, VAULT_EXT, WAL_EXT},
    encode,
    events::{ChangeAction, ChangeNotification, SyncEvent, WalEvent},
    secret::{Secret, SecretId, SecretMeta},
    vault::{Summary, Vault, VaultId},
    wal::{
        snapshot::{SnapShot, SnapShotManager},
        WalProvider,
    },
    ChangePassword, CommitHash, Gatekeeper, PatchProvider,
};

use crate::{
    client::{Error, Result},
    sync::{SyncInfo, SyncKind, SyncStatus},
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
mod helpers;

#[cfg(not(target_arch = "wasm32"))]
mod local_provider;
//mod macros;
#[cfg(target_arch = "wasm32")]
mod memory_provider;
#[cfg(not(target_arch = "wasm32"))]
mod provider_factory;
mod remote_provider;
mod state;
mod sync;

#[cfg(not(target_arch = "wasm32"))]
pub use local_provider::LocalProvider;
#[cfg(not(target_arch = "wasm32"))]
pub use provider_factory::*;
pub use remote_provider::RemoteProvider;

#[cfg(target_arch = "wasm32")]
pub use memory_provider::MemoryProvider;

pub use state::ProviderState;

/// Generic boxed provider.
pub type BoxedProvider<W, P> =
    Box<dyn StorageProvider<W, P> + Send + Sync + 'static>;

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
        let user_dir = documents_dir.join(user_id);
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

/// Trait for storage providers.
///
/// Note we need `Sync` and `Send` super traits as we want
/// to refer to `dyn StorageProvider`.
///
/// See: https://docs.rs/async-trait/latest/async_trait/#dyn-traits
#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait StorageProvider<W, P>: Sync + Send
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    /// Get the state for this storage provider.
    fn state(&self) -> &ProviderState;

    /// Get a mutable reference to the state for this storage provider.
    fn state_mut(&mut self) -> &mut ProviderState;

    /// Compute the storage directory for the user.
    fn dirs(&self) -> &StorageDirs;

    /*
    /// Get the cache.
    fn cache(&self) -> &HashMap<VaultId, (W, P)>;

    /// Get a mutable reference to the cache.
    fn cache_mut(&mut self) -> &mut HashMap<VaultId, (W, P)>;
    */

    /// Get the snapshot manager for this cache.
    fn snapshots(&self) -> Option<&SnapShotManager>;

    /// Take a snapshot of the WAL for the given vault.
    ///
    /// Snapshots must be enabled.
    fn take_snapshot(&self, summary: &Summary) -> Result<(SnapShot, bool)>;

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
    ) -> Result<Vec<(W::Item, WalEvent<'_>)>>;

    /// Update an existing vault by replacing it with a new vault.
    async fn update_vault<'a>(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<WalEvent<'a>>,
    ) -> Result<()>;

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
    ) -> Result<SecretString>;

    /// Compact a WAL file.
    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)>;

    /// Refresh the in-memory vault of the current selection
    /// from the contents of the current WAL file.
    async fn refresh_vault(
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
    async fn open_vault(
        &mut self,
        summary: &Summary,
        passphrase: &str,
    ) -> Result<()>;

    /// Load a vault by reducing it from the WAL stored on disc.
    ///
    /// Remote providers may pull changes beforehand.
    async fn reduce_wal(&mut self, summary: &Summary) -> Result<Vault>;

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
    async fn remove_local_cache(&mut self, summary: &Summary) -> Result<()>;

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

    /// Create a secret in the currently open vault.
    async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
    ) -> Result<SyncEvent<'_>>;

    /// Read a secret in the currently open vault.
    async fn read_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, SyncEvent<'_>)>;

    /// Update a secret in the currently open vault.
    async fn update_secret(
        &mut self,
        id: &SecretId,
        mut meta: SecretMeta,
        secret: Secret,
    ) -> Result<SyncEvent<'_>>;

    /// Delete a secret in the currently open vault.
    async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<SyncEvent<'_>>;

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
    async fn backup_vault_file(&self, summary: &Summary) -> Result<()>;

    /// Remove a vault file and WAL file.
    async fn remove_vault_file(&self, summary: &Summary) -> Result<()>;

}
