//! Storage provider backed by the local filesystem.
use super::{Error, Result};

use async_trait::async_trait;

use secrecy::{ExposeSecret, SecretString};
use sos_core::{
    constants::VAULT_EXT,
    encode,
    events::{SyncEvent, WalEvent},
    vault::{Header, Summary, Vault, VaultId},
    wal::{
        memory::WalMemory,
        snapshot::{SnapShot, SnapShotManager},
        WalProvider,
    },
    ChangePassword, PatchMemory, PatchProvider,
};

#[cfg(not(target_arch = "wasm32"))]
use sos_core::{wal::file::WalFile, PatchFile};

use std::{borrow::Cow, collections::HashMap};

use crate::client::provider::{ProviderState, StorageDirs, StorageProvider};

/// Local storage for a node.
///
/// May be backed by files on disc or in-memory implementations
/// for use in webassembly.
pub struct LocalProvider<W, P> {
    /// State of this storage.
    state: ProviderState,

    /// Directories for file storage.
    ///
    /// For memory based storage the paths will be empty.
    dirs: StorageDirs,

    /// Cache for WAL and patch providers.
    cache: HashMap<VaultId, (W, P)>,

    /// Snapshot manager for WAL files.
    ///
    /// Only available when using disc backing storage.
    snapshots: Option<SnapShotManager>,
}

#[cfg(not(target_arch = "wasm32"))]
impl LocalProvider<WalFile, PatchFile> {
    /// Create new node cache backed by files on disc.
    pub fn new_file_storage(
        dirs: StorageDirs,
    ) -> Result<LocalProvider<WalFile, PatchFile>> {
        if !dirs.documents_dir().is_dir() {
            return Err(Error::NotDirectory(
                dirs.documents_dir().to_path_buf(),
            ));
        }

        let user_dir = dirs.user_dir();
        if !user_dir.exists() {
            std::fs::create_dir(user_dir)?;
        }

        let snapshots = Some(SnapShotManager::new(user_dir)?);

        Ok(Self {
            state: ProviderState::new(true),
            cache: Default::default(),
            dirs,
            snapshots,
        })
    }
}

impl LocalProvider<WalMemory, PatchMemory<'static>> {
    /// Create new local storage backed by memory.
    pub fn new_memory_storage(
    ) -> LocalProvider<WalMemory, PatchMemory<'static>> {
        Self {
            state: ProviderState::new(false),
            dirs: Default::default(),
            cache: Default::default(),
            snapshots: None,
        }
    }
}

#[async_trait]
impl<W, P> StorageProvider<W, P> for LocalProvider<W, P>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    fn state(&self) -> &ProviderState {
        &self.state
    }

    fn state_mut(&mut self) -> &mut ProviderState {
        &mut self.state
    }

    fn dirs(&self) -> &StorageDirs {
        &self.dirs
    }

    fn cache(&self) -> &HashMap<VaultId, (W, P)> {
        &self.cache
    }

    fn cache_mut(&mut self) -> &mut HashMap<VaultId, (W, P)> {
        &mut self.cache
    }

    async fn change_password(
        &mut self,
        vault: &Vault,
        current_passphrase: SecretString,
        new_passphrase: SecretString,
    ) -> Result<SecretString> {
        let (new_passphrase, new_vault, wal_events) =
            ChangePassword::new(vault, current_passphrase, new_passphrase)
                .build()?;

        self.update_vault(vault.summary(), &new_vault, wal_events)?;

        // Refresh the in-memory and disc-based mirror
        self.refresh_vault(vault.summary(), Some(&new_passphrase))?;

        if let Some(keeper) = self.current_mut() {
            if keeper.summary().id() == vault.summary().id() {
                keeper.unlock(new_passphrase.expose_secret())?;
            }
        }

        Ok(new_passphrase)
    }

    async fn create_account(
        &mut self,
        name: Option<String>,
        passphrase: Option<String>,
    ) -> Result<(SecretString, Summary)> {
        self.create(name, passphrase, true).await
    }

    async fn create_vault(
        &mut self,
        name: String,
        passphrase: Option<String>,
    ) -> Result<(SecretString, Summary)> {
        self.create(Some(name), passphrase, false).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn load_vaults(&mut self) -> Result<&[Summary]> {
        self.ensure_dir().await?;

        let storage = self.dirs().vaults_dir();
        let mut summaries = Vec::new();
        let mut contents = tokio::fs::read_dir(&storage).await?;
        while let Some(entry) = contents.next_entry().await? {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if extension == VAULT_EXT {
                    let summary = Header::read_summary_file(path)?;
                    summaries.push(summary);
                }
            }
        }

        self.load_caches(&summaries)?;
        self.state.set_summaries(summaries);
        Ok(self.vaults())
    }

    #[cfg(target_arch = "wasm32")]
    async fn load_vaults(&mut self) -> Result<&[Summary]> {
        Ok(self.vaults())
    }

    async fn remove_vault(&mut self, summary: &Summary) -> Result<()> {
        // Remove local state
        self.remove_local_cache(summary).await?;
        Ok(())
    }

    /// Attempt to set the vault name for a vault.
    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<()> {
        let event = SyncEvent::SetVaultName(Cow::Borrowed(name));
        self.patch_wal(summary, vec![event])?;

        // Update the in-memory name.
        for item in self.state.summaries_mut().iter_mut() {
            if item.id() == summary.id() {
                item.set_name(name.to_string());
            }
        }

        Ok(())
    }

    /// Apply changes to a vault.
    async fn patch_vault(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'_>>,
    ) -> Result<()> {
        self.patch_wal(summary, events)?;
        Ok(())
    }
}

impl<W, P> LocalProvider<W, P>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    #[cfg(not(target_arch = "wasm32"))]
    /// Ensure a directory for a user's vaults.
    pub async fn ensure_dir(&self) -> Result<()> {
        tokio::fs::create_dir_all(self.dirs().vaults_dir()).await?;
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    /// Ensure a directory for a user's vaults.
    pub async fn ensure_dir(&self) -> Result<()> {
        Ok(())
    }

    /// Get the snapshot manager for this cache.
    pub fn snapshots(&self) -> Option<&SnapShotManager> {
        self.snapshots.as_ref()
    }

    /// Take a snapshot of the WAL for the given vault.
    ///
    /// Snapshots must be enabled.
    pub fn take_snapshot(
        &self,
        summary: &Summary,
    ) -> Result<(SnapShot, bool)> {
        let snapshots =
            self.snapshots.as_ref().ok_or(Error::SnapshotsNotEnabled)?;
        let (wal, _) = self
            .cache
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let root_hash = wal.tree().root().ok_or(Error::NoRootCommit)?;
        Ok(snapshots.create(summary.id(), wal.path(), root_hash)?)
    }

    /// Add to the local cache for a vault.
    fn add_local_cache(&mut self, summary: Summary) -> Result<()> {
        // Add to our cache of managed vaults
        self.create_cache_entry(&summary, None)?;

        // Add to the state of managed vaults
        self.state.add_summary(summary);

        Ok(())
    }

    /// Remove the local cache for a vault.
    async fn remove_local_cache(&mut self, summary: &Summary) -> Result<()> {
        // Remove a mirrored vault file if it exists
        self.remove_vault_file(summary).await?;

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
        self.state.remove_summary(summary);

        Ok(())
    }

    fn patch_wal(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'_>>,
    ) -> Result<()> {
        let (wal, patch_file) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        // Store events in a patch file so networking
        // logic can see which events need to be synced
        let _patch = patch_file.append(events.clone())?;

        // Append to the WAL file
        for event in events {
            wal.append_event(event.try_into()?)?;
        }

        Ok(())
    }

    /// Update an existing vault by saving the new vault
    /// and WAL events.
    fn update_vault<'a>(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<WalEvent<'a>>,
    ) -> Result<()> {
        if self.state().mirror() {
            // Write the vault to disc
            let buffer = encode(vault)?;
            self.write_vault_file(summary, &buffer)?;
        }

        // Apply events to the WAL
        let (wal, _) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        wal.clear()?;
        wal.apply(events, None)?;

        Ok(())
    }

    /// Create a new account or vault.
    async fn create(
        &mut self,
        name: Option<String>,
        passphrase: Option<String>,
        _is_account: bool,
    ) -> Result<(SecretString, Summary)> {
        self.ensure_dir().await?;

        let (passphrase, vault, buffer) =
            Vault::new_buffer(name, passphrase)?;
        let summary = vault.summary().clone();

        if self.state().mirror() {
            self.write_vault_file(&summary, &buffer)?;
        }

        // Add the summary to the vaults we are managing
        self.state.add_summary(summary.clone());

        // Initialize the local cache for WAL and Patch
        self.create_cache_entry(&summary, Some(vault))?;

        Ok((passphrase, summary))
    }
}
