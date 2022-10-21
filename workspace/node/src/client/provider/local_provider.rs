//! Storage provider backed by the local filesystem.
use super::{Error, Result};

use async_trait::async_trait;

use secrecy::{ExposeSecret, SecretString};
use sos_core::{
    commit_tree::{CommitPair, CommitTree},
    constants::VAULT_EXT,
    crypto::secret_key::SecretKey,
    decode, encode,
    events::{ChangeAction, ChangeNotification, SyncEvent, WalEvent},
    vault::{Header, Summary, Vault, VaultId},
    wal::{
        memory::WalMemory, reducer::WalReducer, snapshot::SnapShot,
        snapshot::SnapShotManager, WalItem, WalProvider,
    },
    CommitHash, PatchMemory, PatchProvider, Timestamp,
};

#[cfg(not(target_arch = "wasm32"))]
use sos_core::{wal::file::WalFile, PatchFile};

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

use crate::{
    client::provider::{
        fs_adapter, sync, ProviderState, StorageDirs, StorageProvider,
    },
    provider_impl,
    sync::{SyncInfo, SyncKind, SyncStatus},
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

        dirs.ensure()?;

        let snapshots = Some(SnapShotManager::new(dirs.user_dir())?);

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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<W, P> StorageProvider for LocalProvider<W, P>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    provider_impl!();

    /// Create a new account or vault.
    async fn create_vault_or_account(
        &mut self,
        name: Option<String>,
        passphrase: Option<String>,
        _is_account: bool,
    ) -> Result<(SecretString, Summary)> {
        let (passphrase, vault, buffer) =
            Vault::new_buffer(name, passphrase)?;
        let summary = vault.summary().clone();

        if self.state().mirror() {
            self.write_vault_file(&summary, &buffer)?;
        }

        // Add the summary to the vaults we are managing
        self.state_mut().add_summary(summary.clone());

        // Initialize the local cache for WAL and Patch
        self.create_cache_entry(&summary, Some(vault))?;

        Ok((passphrase, summary))
    }

    async fn import_vault(
        &mut self,
        buffer: Vec<u8>,
    ) -> Result<Summary> {
        self.create_account_with_buffer(buffer).await
    }

    async fn create_account_with_buffer(
        &mut self,
        buffer: Vec<u8>,
    ) -> Result<Summary> {
        let vault: Vault = decode(&buffer)?;
        let summary = vault.summary().clone();

        if self.state().mirror() {
            self.write_vault_file(&summary, &buffer)?;
        }

        // Add the summary to the vaults we are managing
        self.state_mut().add_summary(summary.clone());

        // Initialize the local cache for WAL and Patch
        self.create_cache_entry(&summary, Some(vault))?;

        Ok(summary)
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

    #[cfg(not(target_arch = "wasm32"))]
    async fn load_vaults(&mut self) -> Result<&[Summary]> {
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
        let (wal_file, _) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        let (compact_wal, old_size, new_size) = wal_file.compact()?;

        // Need to recreate the WAL file and load the updated
        // commit tree
        *wal_file = compact_wal;

        // Refresh in-memory vault and mirrored copy
        self.refresh_vault(summary, None)?;

        Ok((old_size, new_size))
    }

    fn reduce_wal(&mut self, summary: &Summary) -> Result<Vault> {
        let wal_file = self
            .cache
            .get_mut(summary.id())
            .map(|(w, _)| w)
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        Ok(WalReducer::new().reduce(wal_file)?.build()?)
    }

    async fn remove_vault(&mut self, summary: &Summary) -> Result<()> {
        // Remove the files
        self.remove_vault_file(summary)?;

        // Remove local state
        self.remove_local_cache(summary)?;
        Ok(())
    }

    /// Attempt to set the vault name for a vault.
    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<()> {
        let event = SyncEvent::SetVaultName(Cow::Borrowed(name));
        self.patch(summary, vec![event.into_owned()]).await?;

        // Update the in-memory name.
        for item in self.state.summaries_mut().iter_mut() {
            if item.id() == summary.id() {
                item.set_name(name.to_string());
            }
        }

        Ok(())
    }

    async fn patch(
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

    async fn pull(
        &mut self,
        summary: &Summary,
        _force: bool,
    ) -> Result<SyncInfo> {
        let head = self
            .commit_tree(summary)
            .ok_or(Error::NoRootCommit)?
            .head()?;
        let info = SyncInfo {
            before: (head.clone(), head),
            after: None,
            status: SyncKind::Equal,
        };
        Ok(info)
    }

    async fn push(
        &mut self,
        summary: &Summary,
        _force: bool,
    ) -> Result<SyncInfo> {
        let head = self
            .commit_tree(summary)
            .ok_or(Error::NoRootCommit)?
            .head()?;
        let info = SyncInfo {
            before: (head.clone(), head),
            after: None,
            status: SyncKind::Equal,
        };
        Ok(info)
    }

    async fn status(
        &mut self,
        summary: &Summary,
    ) -> Result<(SyncStatus, Option<usize>)> {
        let head = self
            .commit_tree(summary)
            .ok_or(Error::NoRootCommit)?
            .head()?;
        let pair = CommitPair {
            local: head.clone(),
            remote: head,
        };
        Ok((SyncStatus::Equal(pair), None))
    }
}
