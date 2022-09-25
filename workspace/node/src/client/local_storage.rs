//! Local storage of vaults and WAL files.
use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use http::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use sos_core::{
    commit_tree::{CommitPair, CommitProof, CommitTree, Comparison},
    constants::{PATCH_EXT, WAL_EXT, WAL_IDENTITY},
    crypto::secret_key::SecretKey,
    encode,
    events::{
        ChangeAction, ChangeEvent, ChangeNotification, SyncEvent, WalEvent,
    },
    generate_passphrase,
    secret::SecretRef,
    signer::BoxedSigner,
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

use url::Url;

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
    client::node_state::NodeState,
    sync::{SyncInfo, SyncKind, SyncStatus},
};

#[cfg(not(target_arch = "wasm32"))]
/// Ensure a directory for a user's vaults.
pub fn ensure_user_vaults_dir<D: AsRef<Path>>(
    cache_dir: D,
    signer: &BoxedSigner,
) -> Result<PathBuf> {
    use sos_core::constants::VAULTS_DIR;
    let address = signer.address()?;
    let vaults_dir = cache_dir.as_ref().join(VAULTS_DIR);
    let user_dir = vaults_dir.join(address.to_string());
    std::fs::create_dir_all(&user_dir)?;
    Ok(user_dir)
}

/// Local storage for a node.
///
/// May be backed by files on disc or in-memory implementations
/// for use in webassembly.
pub struct LocalStorage<W, P> {
    /// State of this node.
    state: NodeState,
    /// Directory for the user cache.
    ///
    /// Only available when using disc backing storage.
    user_dir: Option<PathBuf>,
    /// Data for the cache.
    cache: HashMap<Uuid, (W, P)>,
    /// Mirror in-memory contents to vault files.
    mirror: bool,
    /// Snapshot manager for WAL files.
    ///
    /// Only available when using disc backing storage.
    snapshots: Option<SnapShotManager>,
}

impl<W, P> LocalStorage<W, P>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    /// Get the vault summaries for this cache.
    pub fn vaults(&self) -> &[Summary] {
        self.state.summaries()
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

    /// Get the history for a WAL provider.
    pub fn history(
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

    /// Change the password for a vault.
    ///
    /// If the target vault is the currently selected vault
    /// the currently selected vault is unlocked with the new
    /// passphrase on success.
    pub fn change_password(
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

    /// Verify a WAL log.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn verify(&self, summary: &Summary) -> Result<()> {
        use sos_core::commit_tree::wal_commit_tree_file;
        let wal_path = self.wal_path(summary);
        wal_commit_tree_file(&wal_path, true, |_| {})?;
        Ok(())
    }

    /// Verify a WAL log.
    #[cfg(target_arch = "wasm32")]
    pub fn verify(&self, _summary: &Summary) -> Result<()> {
        // NOTE: verify is a noop in WASM when the records
        // NOTE: are stored in memory
        Ok(())
    }

    /// Compact a WAL provider.
    pub fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
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

    /// List the vault summaries.
    pub fn list_vaults(&mut self) -> Result<&[Summary]> {
        /*

        self.load_caches(&summaries)?;

        self.state.set_summaries(summaries);

        Ok(self.vaults())
        */

        todo!();
    }

    /// Get the state for this node cache.
    pub fn state(&self) -> &NodeState {
        &self.state
    }

    /// Create a new account and default login vault.
    pub fn create_account(
        &mut self,
        name: Option<String>,
        passphrase: Option<String>,
    ) -> Result<(SecretString, Summary)> {
        self.create(name, passphrase, true)
    }

    /// Create a new vault.
    pub fn create_vault(
        &mut self,
        name: String,
        passphrase: Option<String>,
    ) -> Result<(SecretString, Summary)> {
        self.create(Some(name), passphrase, false)
    }

    /// Remove a vault.
    pub fn remove_vault(&mut self, summary: &Summary) -> Result<()> {
        todo!("Remove the WAL and vault files...");

        // Remove local state
        self.remove_local_cache(summary)?;

        Ok(())
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
    fn remove_local_cache(&mut self, summary: &Summary) -> Result<()> {
        let current_id = self.current().map(|c| c.id().clone());

        // If the deleted vault is the currently selected
        // vault we must close it
        if let Some(id) = &current_id {
            if id == summary.id() {
                self.close_vault();
            }
        }

        // Remove a mirrored vault file if it exists
        self.remove_vault_file(summary)?;

        // Remove from our cache of managed vaults
        self.cache.remove(summary.id());

        // Remove from the state of managed vaults
        self.state.remove_summary(summary);

        Ok(())
    }

    /// Attempt to set the vault name for a vault.
    pub fn set_vault_name(
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

    /// Load a vault, unlock it and set it as the current vault.
    pub fn open_vault(
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

    /// Load a vault by reducing it from the WAL stored on disc.
    fn get_wal_vault(&mut self, summary: &Summary) -> Result<Vault> {
        // Reduce the WAL to a vault
        let wal = self
            .cache
            .get_mut(summary.id())
            .map(|(w, _)| w)
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let vault = WalReducer::new().reduce(wal)?.build()?;
        Ok(vault)
    }

    /// Close the currently selected vault.
    pub fn close_vault(&mut self) {
        self.state.close_vault();
    }

    /// Get the current in-memory vault access.
    pub fn current(&self) -> Option<&Gatekeeper> {
        self.state.current()
    }

    /// Get a mutable reference to the current in-memory vault access.
    pub fn current_mut(&mut self) -> Option<&mut Gatekeeper> {
        self.state.current_mut()
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
        signer: BoxedSigner,
        cache_dir: D,
    ) -> Result<LocalStorage<WalFile, PatchFile>> {
        if !cache_dir.as_ref().is_dir() {
            return Err(Error::NotDirectory(
                cache_dir.as_ref().to_path_buf(),
            ));
        }

        let user_dir = ensure_user_vaults_dir(cache_dir, &signer)?;
        let snapshots = Some(SnapShotManager::new(&user_dir)?);

        Ok(Self {
            state: Default::default(),
            user_dir: Some(user_dir),
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
            user_dir: None,
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
    fn create(
        &mut self,
        name: Option<String>,
        passphrase: Option<String>,
        is_account: bool,
    ) -> Result<(SecretString, Summary)> {
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

    fn wal_path(&self, summary: &Summary) -> PathBuf {
        if let Some(user_dir) = &self.user_dir {
            let wal_name = format!("{}.{}", summary.id(), WAL_EXT);
            user_dir.join(&wal_name)
        } else {
            PathBuf::from("/dev/memory/wal")
        }
    }

    fn vault_path(&self, summary: &Summary) -> PathBuf {
        if let Some(user_dir) = &self.user_dir {
            let wal_name = format!("{}.{}", summary.id(), Vault::extension());
            user_dir.join(&wal_name)
        } else {
            PathBuf::from("/dev/memory/vault")
        }
    }

    fn patch_path(&self, summary: &Summary) -> PathBuf {
        if let Some(user_dir) = &self.user_dir {
            let patch_name = format!("{}.{}", summary.id(), PATCH_EXT);
            user_dir.join(&patch_name)
        } else {
            PathBuf::from("/dev/memory/patch")
        }
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
    fn backup_vault_file(&self, summary: &Summary) -> Result<()> {
        use sos_core::constants::VAULT_BACKUP_EXT;

        // Move our cached vault to a backup
        let vault_path = self.vault_path(summary);

        if vault_path.exists() {
            let mut vault_backup = vault_path.clone();
            vault_backup.set_extension(VAULT_BACKUP_EXT);
            std::fs::rename(&vault_path, &vault_backup)?;
            tracing::debug!(
                vault = ?vault_path, backup = ?vault_backup, "vault backup");
        }

        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    fn backup_vault_file(&self, _summary: &Summary) -> Result<()> {
        Ok(())
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn remove_vault_file(&self, summary: &Summary) -> Result<()> {
        // Remove local vault mirror if it exists
        let vault_path = self.vault_path(summary);
        if vault_path.exists() {
            std::fs::remove_file(vault_path)?;
        }

        // Rename the local WAL file so recovery is still possible
        let wal_path = self.vault_path(summary);
        if wal_path.exists() {
            let mut wal_path_backup = wal_path.clone();
            wal_path_backup.set_extension(WAL_DELETED_EXT);
            std::fs::rename(wal_path, wal_path_backup)?;
        }
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    fn remove_vault_file(&self, _summary: &Summary) -> Result<()> {
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn remove_file(file: &PathBuf) -> Result<()> {
    std::fs::remove_file(file)?;
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn remove_file(_file: &PathBuf) -> Result<()> {
    Ok(())
}
