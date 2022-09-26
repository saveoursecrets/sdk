//! Storage provider trait.

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use std::{
    borrow::Cow,
    collections::HashMap,
    path::{Path, PathBuf},
};

use sos_core::{
    commit_tree::CommitTree,
    constants::{PATCH_EXT, VAULTS_DIR, VAULT_EXT, WAL_DELETED_EXT, WAL_EXT},
    crypto::secret_key::SecretKey,
    encode,
    events::{SyncEvent, WalEvent},
    secret::{Secret, SecretId, SecretMeta},
    vault::{Summary, Vault, VaultId},
    wal::{reducer::WalReducer, WalProvider},
    Gatekeeper, PatchProvider,
};

use crate::client::{Error, Result};

mod fs_adapter;
mod local_provider;
mod macros;
mod remote_provider;
mod state;

pub use local_provider::LocalProvider;
pub use state::ProviderState;

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
    fn state(&self) -> &ProviderState;

    /// Get a mutable reference to the state for this storage provider.
    fn state_mut(&mut self) -> &mut ProviderState;

    /// Compute the storage directory for the user.
    fn dirs(&self) -> &StorageDirs;

    /// Get the cache.
    fn cache(&self) -> &HashMap<VaultId, (W, P)>;

    /// Get a mutable reference to the cache.
    fn cache_mut(&mut self) -> &mut HashMap<VaultId, (W, P)>;

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
    ) -> Result<Vec<(W::Item, WalEvent<'_>)>> {
        let (wal, _) = self
            .cache()
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let mut records = Vec::new();
        for record in wal.iter()? {
            let record = record?;
            let event = wal.event_data(&record)?;
            records.push((record, event));
        }
        Ok(records)
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
    ) -> Result<SecretString>;

    /// Compact a WAL file.
    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        let (wal, _) = self
            .cache_mut()
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        let (compact_wal, old_size, new_size) = wal.compact()?;

        // Need to recreate the WAL file and load the updated
        // commit tree
        *wal = compact_wal;

        // Refresh in-memory vault and mirrored copy
        self.refresh_vault(summary, None)?;

        Ok((old_size, new_size))
    }

    /// Refresh the in-memory vault of the current selection
    /// from the contents of the current WAL file.
    fn refresh_vault(
        &mut self,
        summary: &Summary,
        new_passphrase: Option<&SecretString>,
    ) -> Result<()> {
        let wal = self
            .cache_mut()
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
    async fn open_vault(
        &mut self,
        summary: &Summary,
        passphrase: &str,
    ) -> Result<()> {
        let vault = self.get_wal_vault(summary).await?;
        let vault_path = self.vault_path(summary);
        if self.state().mirror() {
            let vault_path = self.vault_path(summary);
            if !vault_path.exists() {
                let buffer = encode(&vault)?;
                self.write_vault_file(summary, &buffer)?;
            }
        };
        self.state_mut().open_vault(passphrase, vault, vault_path)?;
        Ok(())
    }

    /// Load a vault by reducing it from the WAL stored on disc.
    ///
    /// Remote providers may pull changes beforehand.
    async fn get_wal_vault(&mut self, summary: &Summary) -> Result<Vault> {
        // Reduce the WAL to a vault
        let wal = self
            .cache_mut()
            .get_mut(summary.id())
            .map(|(w, _)| w)
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        Ok(WalReducer::new().reduce(wal)?.build()?)
    }

    /// Close the currently selected vault.
    fn close_vault(&mut self) {
        self.state_mut().close_vault();
    }

    /// Get a reference to the commit tree for a WAL file.
    fn commit_tree(&self, summary: &Summary) -> Option<&CommitTree> {
        self.cache().get(summary.id()).map(|(wal, _)| wal.tree())
    }

    /// Create new patch and WAL cache entries.
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
        self.cache_mut().insert(*summary.id(), (wal, patch_file));
        Ok(())
    }

    /// Create a cache entry for each summary if it does not
    /// already exist.
    fn load_caches(&mut self, summaries: &[Summary]) -> Result<()> {
        for summary in summaries {
            // Ensure we don't overwrite existing data
            if self.cache().get(summary.id()).is_none() {
                self.create_cache_entry(summary, None)?;
            }
        }
        Ok(())
    }

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
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
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
        self.patch_vault(&summary, vec![event.clone()]).await?;
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
        self.patch_vault(&summary, vec![event.clone()]).await?;
        Ok(event)
    }

    /// Verify a WAL log.
    #[cfg(not(target_arch = "wasm32"))]
    fn verify(&self, summary: &Summary) -> Result<()> {
        use sos_core::commit_tree::wal_commit_tree_file;
        let wal_path = self.wal_path(summary);
        wal_commit_tree_file(&wal_path, true, |_| {})?;
        Ok(())
    }

    /// Verify a WAL log.
    #[cfg(target_arch = "wasm32")]
    fn verify(&self, _summary: &Summary) -> Result<()> {
        // NOTE: verify is a noop in WASM when the records
        // NOTE: are stored in memory
        Ok(())
    }

    /// Write the buffer for a vault to disc.
    #[cfg(not(target_arch = "wasm32"))]
    fn write_vault_file(
        &self,
        summary: &Summary,
        buffer: &[u8],
    ) -> Result<()> {
        use std::io::Write;
        let vault_path = self.vault_path(&summary);
        // FIXME: use tokio writer?
        let mut file = std::fs::File::create(vault_path)?;
        file.write_all(buffer)?;
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
    async fn backup_vault_file(&self, summary: &Summary) -> Result<()> {
        use sos_core::constants::VAULT_BACKUP_EXT;

        // Move our cached vault to a backup
        let vault_path = self.vault_path(summary);

        if vault_path.exists() {
            let mut vault_backup = vault_path.clone();
            vault_backup.set_extension(VAULT_BACKUP_EXT);
            fs_adapter::rename(&vault_path, &vault_backup).await?;
            tracing::debug!(
                vault = ?vault_path, backup = ?vault_backup, "vault backup");
        }

        Ok(())
    }

    /// Create a backup of a vault file.
    #[cfg(target_arch = "wasm32")]
    async fn backup_vault_file(&self, _summary: &Summary) -> Result<()> {
        Ok(())
    }

    /// Remove a vault file and WAL file.
    #[cfg(not(target_arch = "wasm32"))]
    async fn remove_vault_file(&self, summary: &Summary) -> Result<()> {
        // Remove local vault mirror if it exists
        let vault_path = self.vault_path(summary);
        if vault_path.exists() {
            fs_adapter::remove_file(&vault_path).await?;
        }

        // Rename the local WAL file so recovery is still possible
        let wal_path = self.wal_path(summary);
        if wal_path.exists() {
            let mut wal_path_backup = wal_path.clone();
            wal_path_backup.set_extension(WAL_DELETED_EXT);
            fs_adapter::rename(wal_path, wal_path_backup).await?;
        }
        Ok(())
    }

    /// Remove a vault file and WAL file.
    #[cfg(target_arch = "wasm32")]
    async fn remove_vault_file(&self, _summary: &Summary) -> Result<()> {
        Ok(())
    }
}
