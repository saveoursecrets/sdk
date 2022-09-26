//! Storage provider backed by the local filesystem.
use super::{Error, Result};

use async_trait::async_trait;

use secrecy::{ExposeSecret, SecretString};
use sos_core::{
    commit_tree::{CommitPair, CommitProof, CommitTree, Comparison},
    constants::{PATCH_EXT, WAL_EXT, WAL_IDENTITY, VAULTS_DIR},
    crypto::secret_key::SecretKey,
    encode,
    events::{
        ChangeAction, ChangeEvent, ChangeNotification, SyncEvent, WalEvent,
    },
    generate_passphrase,
    vault::{Header, Summary, Vault},
    wal::{
        memory::WalMemory,
        reducer::WalReducer,
        snapshot::{SnapShot, SnapShotManager},
        WalProvider,
    },
    ChangePassword, CommitHash, FileIdentity, Gatekeeper, PatchMemory,
    PatchProvider,
};

#[cfg(not(target_arch = "wasm32"))]
use sos_core::{constants::WAL_DELETED_EXT, wal::file::WalFile, PatchFile};

#[cfg(not(target_arch = "wasm32"))]
use std::{io::Write, path::Path};

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    path::PathBuf,
};
use uuid::Uuid;

use crate::{
    client::{node_state::NodeState, storage::StorageProvider},
    sync::{SyncInfo, SyncKind, SyncStatus},
};

/// Local storage for a node.
///
/// May be backed by files on disc or in-memory implementations
/// for use in webassembly.
pub struct LocalStorage<W, P> {
    /// State of this storage.
    state: NodeState,

    /// Directory for file storage.
    ///
    /// Only available when using disc backing storage; for 
    /// memory based storage this will be an empty path.
    storage_dir: PathBuf,

    /// Identifier for the user so that storage is 
    /// segregated by user identifier.
    ///
    /// The value should match the address of the
    /// user's signing key.
    user_id: String,

    /// Cache for WAL and patch providers.
    cache: HashMap<Uuid, (W, P)>,

    /// Mirror in-memory contents to vault files.
    mirror: bool,

    /// Snapshot manager for WAL files.
    ///
    /// Only available when using disc backing storage.
    snapshots: Option<SnapShotManager>,
}

#[async_trait]
impl<W, P> StorageProvider<W, P> for LocalStorage<W, P>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    fn state(&self) -> &NodeState {
        &self.state
    }

    fn state_mut(&mut self) -> &mut NodeState {
        &mut self.state
    }

    fn storage_dir(&self) -> PathBuf {
        self.storage_dir.join(&self.user_id).join(VAULTS_DIR)
    }

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

    /// Compact a WAL file.
    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        let (wal, _) = self
            .cache
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

    fn open_vault(
        &mut self,
        summary: &Summary,
        passphrase: &str,
    ) -> Result<()> {
        let vault = self.get_wal_vault(summary)?;
        let vault_path = if self.mirror {
            let vault_path = self.vault_path(summary);
            if !vault_path.exists() {
                let buffer = encode(&vault)?;
                self.write_vault_file(summary, &buffer)?;
            }
            Some(vault_path)
        } else {
            None
        };

        self.state.open_vault(passphrase, vault, vault_path)?;

        Ok(())
    }

    fn close_vault(&mut self) {
        self.state.close_vault();
    }
}

impl<W, P> LocalStorage<W, P>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{

    #[cfg(not(target_arch = "wasm32"))]
    /// Ensure a directory for a user's vaults.
    pub async fn ensure_dir(&self) -> Result<()> {
        tokio::fs::create_dir_all(self.storage_dir()).await?;
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

    /// List the vault summaries.
    pub async fn list_vaults(&mut self) -> Result<&[Summary]> {
        /*

        self.load_caches(&summaries)?;

        self.state.set_summaries(summaries);

        Ok(self.vaults())
        */

        todo!();
    }

    /// Add to the local cache for a vault.
    fn add_local_cache(&mut self, summary: Summary) -> Result<()> {
        // Add to our cache of managed vaults
        self.init_local_cache(&summary, None)?;

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
        let patch = patch_file.append(events.clone())?;

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
        if self.mirror {
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

    /// Load a vault by reducing it from the WAL stored on disc.
    fn get_wal_vault(&mut self, summary: &Summary) -> Result<Vault> {
        // Reduce the WAL to a vault
        let wal = self
            .cache
            .get_mut(summary.id())
            .map(|(w, _)| w)
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        Ok(WalReducer::new().reduce(wal)?.build()?)
    }

    /// Get a reference to the commit tree for a WAL file.
    pub fn wal_tree(&self, summary: &Summary) -> Option<&CommitTree> {
        self.cache.get(summary.id()).map(|(wal, _)| wal.tree())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl LocalStorage<WalFile, PatchFile> {
    /// Create new node cache backed by files on disc.
    pub fn new_file_storage<D: AsRef<Path>>(
        storage_dir: D,
        user_id: String,
    ) -> Result<LocalStorage<WalFile, PatchFile>> {
        if !storage_dir.as_ref().is_dir() {
            return Err(Error::NotDirectory(
                storage_dir.as_ref().to_path_buf(),
            ));
        }

        let user_dir = storage_dir.as_ref().join(&user_id);

        if !user_dir.exists() {
            std::fs::create_dir(&user_dir)?;
        }

        //let user_dir = ensure_user_vaults_dir(cache_dir, &signer)?;
        let snapshots = Some(
            SnapShotManager::new(user_dir)?);

        Ok(Self {
            state: Default::default(),
            storage_dir: storage_dir.as_ref().to_path_buf(),
            user_id,
            cache: Default::default(),
            mirror: true,
            snapshots,
        })
    }
}

impl LocalStorage<WalMemory, PatchMemory<'static>> {
    /// Create new local storage backed by memory.
    pub fn new_memory_storage(
    ) -> LocalStorage<WalMemory, PatchMemory<'static>> {
        Self {
            state: Default::default(),
            storage_dir: PathBuf::from(""),
            user_id: String::new(),
            cache: Default::default(),
            mirror: false,
            snapshots: None,
        }
    }
}

impl<W, P> LocalStorage<W, P>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    /// Create a new account or vault.
    async fn create(
        &mut self,
        name: Option<String>,
        passphrase: Option<String>,
        is_account: bool,
    ) -> Result<(SecretString, Summary)> {

        self.ensure_dir().await?;

        let (passphrase, vault, buffer) = self.new_vault(name, passphrase)?;
        let summary = vault.summary().clone();

        if self.mirror {
            self.write_vault_file(&summary, &buffer)?;
        }

        // Add the summary to the vaults we are managing
        self.state.add_summary(summary.clone());

        // Initialize the local cache for WAL and Patch
        self.init_local_cache(&summary, Some(vault))?;

        Ok((passphrase, summary))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn write_vault_file(
        &self,
        summary: &Summary,
        buffer: &[u8],
    ) -> Result<()> {
        let vault_path = self.vault_path(&summary);
        // FIXME: use tokio writer?
        let mut file = std::fs::File::create(vault_path)?;
        file.write_all(buffer)?;
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    fn write_vault_file(
        &self,
        _summary: &Summary,
        _buffer: &[u8],
    ) -> Result<()> {
        Ok(())
    }

    fn new_vault(
        &self,
        name: Option<String>,
        passphrase: Option<String>,
    ) -> Result<(SecretString, Vault, Vec<u8>)> {
        let passphrase = if let Some(passphrase) = passphrase {
            secrecy::Secret::new(passphrase)
        } else {
            let (passphrase, _) = generate_passphrase()?;
            passphrase
        };
        let mut vault: Vault = Default::default();
        if let Some(name) = name {
            vault.set_name(name);
        }
        vault.initialize(passphrase.expose_secret())?;
        let buffer = encode(&vault)?;
        Ok((passphrase, vault, buffer))
    }

    fn load_caches(&mut self, summaries: &[Summary]) -> Result<()> {
        for summary in summaries {
            // Ensure we don't overwrite existing data
            if self.cache.get(summary.id()).is_none() {
                self.init_local_cache(summary, None)?;
            }
        }
        Ok(())
    }

    fn init_local_cache(
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

    // Refresh the in-memory vault of the current selection
    // from the contents of the current WAL file.
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
        if self.mirror {
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

    #[cfg(not(target_arch = "wasm32"))]
    async fn backup_vault_file(&self, summary: &Summary) -> Result<()> {
        use sos_core::constants::VAULT_BACKUP_EXT;

        // Move our cached vault to a backup
        let vault_path = self.vault_path(summary);

        if vault_path.exists() {
            let mut vault_backup = vault_path.clone();
            vault_backup.set_extension(VAULT_BACKUP_EXT);
            path_adapter::rename(&vault_path, &vault_backup).await?;
            tracing::debug!(
                vault = ?vault_path, backup = ?vault_backup, "vault backup");
        }

        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    async fn backup_vault_file(&self, _summary: &Summary) -> Result<()> {
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn remove_vault_file(&self, summary: &Summary) -> Result<()> {
        // Remove local vault mirror if it exists
        let vault_path = self.vault_path(summary);
        if vault_path.exists() {
            path_adapter::remove_file(&vault_path).await?;
        }

        // Rename the local WAL file so recovery is still possible
        let wal_path = self.wal_path(summary);
        if wal_path.exists() {
            let mut wal_path_backup = wal_path.clone();
            wal_path_backup.set_extension(WAL_DELETED_EXT);
            path_adapter::rename(wal_path, wal_path_backup).await?;
        }
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    async fn remove_vault_file(&self, _summary: &Summary) -> Result<()> {
        Ok(())
    }
}

mod path_adapter {

    #[cfg(not(target_arch = "wasm32"))]
    pub use fs::*;

    #[cfg(not(target_arch = "wasm32"))]
    mod fs {
        use crate::client::Result;
        use std::path::Path;

        pub async fn remove_file(path: impl AsRef<Path>) -> Result<()> {
            Ok(tokio::fs::remove_file(path).await?)
        }

        pub async fn rename(
            from: impl AsRef<Path>,
            to: impl AsRef<Path>,
        ) -> Result<()> {
            Ok(tokio::fs::rename(from, to).await?)
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub use noop::*;

    #[cfg(target_arch = "wasm32")]
    mod noop {
        use crate::client::Result;
        use std::path::Path;

        pub async fn remove_file(_path: impl AsRef<Path>) -> Result<()> {
            Ok(())
        }

        pub async fn rename(
            _from: impl AsRef<Path>,
            _to: impl AsRef<Path>,
        ) -> Result<()> {
            Ok(())
        }
    }
}
