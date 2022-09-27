//! Storage provider backed by the local filesystem.
use super::{Error, Result};

use async_trait::async_trait;

use secrecy::SecretString;
use sos_core::{
    constants::VAULT_EXT,
    encode,
    events::{ChangeAction, ChangeNotification, SyncEvent, WalEvent},
    vault::{Header, Summary, Vault, VaultId},
    wal::{memory::WalMemory, snapshot::SnapShotManager, WalProvider},
    PatchMemory, PatchProvider,
};

#[cfg(not(target_arch = "wasm32"))]
use sos_core::{wal::file::WalFile, PatchFile};

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

use crate::client::provider::{
    helpers, sync, ProviderState, StorageDirs, StorageProvider,
};

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

    fn snapshots(&self) -> Option<&SnapShotManager> {
        self.snapshots.as_ref()
    }

    /// Create a new account or vault.
    async fn create_vault_or_account(
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
            helpers::write_vault_file(self, &summary, &buffer).await?;
        }

        // Add the summary to the vaults we are managing
        self.state_mut().add_summary(summary.clone());

        // Initialize the local cache for WAL and Patch
        self.create_cache_entry(&summary, Some(vault))?;

        Ok((passphrase, summary))
    }

    async fn handle_change(
        &mut self,
        change: ChangeNotification,
    ) -> Result<(bool, HashSet<ChangeAction>)> {
        let actions = sync::handle_change(self, change).await?;
        Ok((false, actions))
    }

    async fn update_vault<'a>(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<WalEvent<'a>>,
    ) -> Result<()> {
        if self.state().mirror() {
            // Write the vault to disc
            let buffer = encode(vault)?;
            helpers::write_vault_file(self, summary, &buffer).await?;
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

    async fn refresh_vault(
        &mut self,
        summary: &Summary,
        new_passphrase: Option<&SecretString>,
    ) -> Result<()> {
        helpers::refresh_vault(self, summary, new_passphrase).await
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

    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        helpers::compact(self, summary).await
    }

    async fn reduce_wal(&mut self, summary: &Summary) -> Result<Vault> {
        helpers::reduce_wal(self, summary).await
    }

    async fn remove_vault(&mut self, summary: &Summary) -> Result<()> {
        // Remove the files
        self.remove_vault_file(summary).await?;

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
        self.patch_vault(summary, vec![event.into_owned()]).await?;

        // Update the in-memory name.
        for item in self.state.summaries_mut().iter_mut() {
            if item.id() == summary.id() {
                item.set_name(name.to_string());
            }
        }

        Ok(())
    }

    async fn open_vault(
        &mut self,
        summary: &Summary,
        passphrase: &str,
    ) -> Result<()> {
        helpers::open_vault(self, summary, passphrase).await
    }

    async fn patch_vault(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'static>>,
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
}
