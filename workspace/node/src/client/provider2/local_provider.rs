//! Storage provider backed by the local filesystem.
use super::{Error, Result};

use async_trait::async_trait;

use secrecy::{SecretString, ExposeSecret};
use sos_core::{
    commit_tree::{CommitPair, CommitTree},
    constants::VAULT_EXT,
    decode, encode,
    events::{ChangeAction, ChangeNotification, SyncEvent, WalEvent},
    vault::{Header, Summary, Vault, VaultId},
    secret::{Secret, SecretMeta, SecretId},
    wal::{memory::WalMemory, snapshot::SnapShotManager, WalProvider, snapshot::SnapShot},
    PatchMemory, PatchProvider,
    ChangePassword,
};

#[cfg(not(target_arch = "wasm32"))]
use sos_core::{wal::file::WalFile, PatchFile};

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};

use crate::{
        client::provider2::{
        helpers, sync, ProviderState, StorageDirs, StorageProvider,
        fs_adapter,
    },
    sync::{SyncInfo, SyncStatus, SyncKind},
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

    /*
    fn cache(&self) -> &HashMap<VaultId, (W, P)> {
        &self.cache
    }

    fn cache_mut(&mut self) -> &mut HashMap<VaultId, (W, P)> {
        &mut self.cache
    }
    */

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

    async fn create_account_with_buffer(
        &mut self,
        buffer: Vec<u8>,
    ) -> Result<Summary> {
        let vault: Vault = decode(&buffer)?;
        let summary = vault.summary().clone();

        if self.state().mirror() {
            helpers::write_vault_file(self, &summary, &buffer).await?;
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
        self.patch(summary, vec![event.into_owned()]).await?;

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






































    /// Close the currently selected vault.
    fn close_vault(&mut self) {
        self.state_mut().close_vault();
    }

    /// Get a reference to the commit tree for a WAL file.
    fn commit_tree(&self, summary: &Summary) -> Option<&CommitTree> {
        self.cache.get(summary.id()).map(|(wal, _)| wal.tree())
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

        self.cache.insert(*summary.id(), (wal, patch_file));
        Ok(())
    }


    /// Remove the local cache for a vault.
    async fn remove_local_cache(&mut self, summary: &Summary) -> Result<()> {
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

    /// Add to the local cache for a vault.
    fn add_local_cache(&mut self, summary: Summary) -> Result<()> {
        // Add to our cache of managed vaults
        self.create_cache_entry(&summary, None)?;

        // Add to the state of managed vaults
        self.state_mut().add_summary(summary);
        Ok(())
    }

    /// Create a cache entry for each summary if it does not
    /// already exist.
    fn load_caches(&mut self, summaries: &[Summary]) -> Result<()> {
        for summary in summaries {
            // Ensure we don't overwrite existing data
            if self.cache.get(summary.id()).is_none() {
                self.create_cache_entry(summary, None)?;
            }
        }
        Ok(())
    }

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
    async fn read_secret(
        &mut self,
        id: &SecretId,
    ) -> Result<(SecretMeta, Secret, SyncEvent<'_>)> {
        let keeper = self.current_mut().ok_or(Error::NoOpenVault)?;
        let _summary = keeper.summary().clone();
        let result = keeper.read(id)?.ok_or(Error::SecretNotFound(*id))?;
        Ok(result)
    }
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
        use sos_core::constants::WAL_DELETED_EXT;

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
        self.refresh_vault(vault.summary(), Some(&new_passphrase))
            .await?;

        if let Some(keeper) = self.current_mut() {
            if keeper.summary().id() == vault.summary().id() {
                keeper.unlock(new_passphrase.expose_secret())?;
            }
        }

        Ok(new_passphrase)
    }

    /// Get the history of events for a vault.
    fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(W::Item, WalEvent<'_>)>> {
        let (wal, _) = self
            .cache
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


    /// Take a snapshot of the WAL for the given vault.
    ///
    /// Snapshots must be enabled.
    fn take_snapshot(&self, summary: &Summary) -> Result<(SnapShot, bool)> {
        let snapshots = self.snapshots().ok_or(Error::SnapshotsNotEnabled)?;
        let (wal_file, _) = self
            .cache
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let root_hash = wal_file.tree().root().ok_or(Error::NoRootCommit)?;
        Ok(snapshots.create(summary.id(), wal_file.path(), root_hash)?)
    }
}
