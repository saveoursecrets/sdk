//! Storage provider trait.

use async_trait::async_trait;
use secrecy::SecretString;
use std::path::{Path, PathBuf};

use sos_core::{
    commit_tree::CommitTree,
    constants::{PATCH_EXT, VAULTS_DIR, VAULT_EXT, WAL_EXT},
    events::{SyncEvent, WalEvent},
    secret::{Secret, SecretId, SecretMeta},
    vault::{Header, Summary, Vault},
    wal::WalProvider,
    Gatekeeper, PatchProvider,
};

use crate::client::{node_state::NodeState, Error, Result};

/// Encapsulates the paths for vault storage.
#[derive(Default)]
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
#[async_trait]
pub trait StorageProvider<W, P>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    /// Get the state for this storage provider.
    fn state(&self) -> &NodeState;

    /// Get a mutable reference to the state for this storage provider.
    fn state_mut(&mut self) -> &mut NodeState;

    /// Compute the storage directory for the user.
    fn dirs(&self) -> &StorageDirs;

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

    /// Create a new account and default login vault.
    async fn create_account(
        &mut self,
        name: Option<String>,
        passphrase: Option<String>,
    ) -> Result<(SecretString, Summary)>;

    /// Create a new vault.
    async fn create_vault(
        &mut self,
        name: String,
        passphrase: Option<String>,
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
    ) -> Result<()>;

    /// Close the currently selected vault.
    fn close_vault(&mut self);

    /// Verify a WAL log.
    fn verify(&self, summary: &Summary) -> Result<()>;

    /// Get a reference to the commit tree for a WAL file.
    fn commit_tree(&self, summary: &Summary) -> Option<&CommitTree>;

    /// Apply changes to a vault.
    async fn patch_vault(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'_>>,
    ) -> Result<()>;

    /// Create a secret in the currently open vault.
    async fn create_secret(
        &mut self,
        meta: SecretMeta,
        secret: Secret,
    ) -> Result<SyncEvent<'_>> {
        let mut keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        let event = keeper.create(meta, secret)?.into_owned();
        self.patch_vault(&summary, vec![event.clone()]).await?;
        Ok(event)
    }

    /// Read a secret in the currently open vault.
    async fn read_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, SyncEvent<'_>)> {
        let mut keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        let result = keeper.read(id)?
            .ok_or(Error::SecretNotFound(*id))?;
        Ok(result)
    }

    /// Update a secret in the currently open vault.
    async fn update_secret(
        &mut self,
        id: &SecretId,
        mut meta: SecretMeta,
        secret: Secret,
    ) -> Result<SyncEvent<'_>> {
        let mut keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        meta.touch();
        let event = keeper.update(id, meta, secret)?
            .ok_or(Error::SecretNotFound(*id))?;
        let event = event.into_owned();
        self.patch_vault(&summary, vec![event.clone()]).await?;
        Ok(event)
    }

    /// Delete a secret in the currently open vault.
    async fn delete_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<SyncEvent<'_>> {
        let mut keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let summary = keeper.summary().clone();
        let event = keeper.delete(id)?
            .ok_or(Error::SecretNotFound(*id))?;
        let event = event.into_owned();
        self.patch_vault(&summary, vec![event.clone()]).await?;
        Ok(event)
    }
}
