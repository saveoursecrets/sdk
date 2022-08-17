//! Caching implementation.
use super::{Error, Result};
use crate::client::net::RpcClient;

use async_recursion::async_recursion;
use http::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use sos_core::{
    commit_tree::{CommitPair, CommitProof, CommitTree, Comparison},
    constants::{PATCH_EXT, VAULT_BACKUP_EXT, WAL_EXT, WAL_IDENTITY},
    encode,
    events::{
        ChangeAction, ChangeEvent, ChangeNotification, SyncEvent, WalEvent,
    },
    generate_passphrase,
    secret::SecretRef,
    signer::BoxedSigner,
    vault::{Summary, Vault},
    wal::{
        memory::WalMemory,
        reducer::WalReducer,
        snapshot::{SnapShot, SnapShotManager},
        WalProvider,
    },
    ChangePassword, CommitHash, FileIdentity, Gatekeeper, PatchMemory,
    PatchProvider, VaultFileAccess,
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

use crate::sync::{SyncInfo, SyncKind, SyncStatus};

fn assert_proofs_eq(
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

/// Manages the state of a node.
#[derive(Default)]
pub struct NodeState {
    /// Vaults managed by this state.
    summaries: Vec<Summary>,
    /// Currently selected in-memory vault.
    current: Option<Gatekeeper>,
}

impl NodeState {
    /// Get the current in-memory vault access.
    pub fn current(&self) -> Option<&Gatekeeper> {
        self.current.as_ref()
    }

    /// Get a mutable reference to the current in-memory vault access.
    pub fn current_mut(&mut self) -> Option<&mut Gatekeeper> {
        self.current.as_mut()
    }

    /// Get the vault summaries this state is managing.
    pub fn summaries(&self) -> &[Summary] {
        self.summaries.as_slice()
    }

    /// Get the vault summaries this state is managing.
    pub fn summaries_mut(&mut self) -> &mut [Summary] {
        self.summaries.as_mut_slice()
    }

    /// Set the summaries for this state.
    pub fn set_summaries(&mut self, summaries: Vec<Summary>) {
        self.summaries = summaries;
        self.summaries.sort();
    }

    /// Add a summary to this state.
    pub fn add_summary(&mut self, summary: Summary) {
        self.summaries.push(summary);
        self.summaries.sort();
    }

    /// Remove a summary from this state.
    pub fn remove_summary(&mut self, summary: &Summary) {
        let index =
            self.summaries.iter().position(|s| s.id() == summary.id());
        if let Some(index) = index {
            self.summaries.remove(index);
            self.summaries.sort();
        }
    }

    /// Attempt to find a summary in this state.
    pub fn find_vault(&self, vault: &SecretRef) -> Option<&Summary> {
        match vault {
            SecretRef::Name(name) => {
                self.summaries.iter().find(|s| s.name() == name)
            }
            SecretRef::Id(id) => self.summaries.iter().find(|s| s.id() == id),
        }
    }

    /// Set the current vault and unlock it.
    fn open_vault(
        &mut self,
        passphrase: &str,
        vault: Vault,
        vault_path: Option<PathBuf>,
    ) -> Result<()> {
        let mut keeper = if let Some(vault_path) = vault_path {
            let mirror = Box::new(VaultFileAccess::new(vault_path)?);
            Gatekeeper::new_mirror(vault, mirror)
        } else {
            Gatekeeper::new(vault)
        };
        keeper
            .unlock(passphrase)
            .map_err(|_| Error::VaultUnlockFail)?;
        keeper.create_index()?;
        self.current = Some(keeper);
        Ok(())
    }

    /// Close the currently open vault.
    ///
    /// When a vault is open it is locked before being closed.
    ///
    /// If no vault is open this is a noop.
    fn close_vault(&mut self) {
        if let Some(current) = self.current_mut() {
            current.lock();
        }
        self.current = None;
    }
}

/// Local data cache for a node.
///
/// May be backed by files on disc or in-memory implementations
/// for use in webassembly.
pub struct NodeCache<W, P> {
    /// State of this node.
    state: NodeState,
    /// Client to use for server communication.
    client: RpcClient,
    /// Directory for the user cache.
    ///
    /// Only available when using disc backing storage.
    user_dir: Option<PathBuf>,
    /// Data for the cache.
    cache: HashMap<Uuid, (W, P)>,
    /// Mirror WAL files and in-memory contents to vault files
    mirror: bool,
    /// Snapshots manager for WAL files.
    ///
    /// Only available when using disc backing storage.
    snapshots: Option<SnapShotManager>,
}

impl<W, P> NodeCache<W, P>
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

    /// Get the signer for this node cache.
    pub fn signer(&self) -> &BoxedSigner {
        self.client.signer()
    }

    /// Get the client.
    pub fn client(&self) -> &RpcClient {
        &self.client
    }

    /// Attempt to open an authenticated, encrypted session.
    ///
    /// Must be called before using any other methods that
    /// communicate over the network to prepare the client session.
    pub async fn authenticate(&mut self) -> Result<()> {
        Ok(self.client.authenticate().await?)
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
    pub async fn change_password(
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
    pub async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        let (wal, _) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        let (compact_wal, old_size, new_size) = wal.compact()?;

        // Need to recreate the WAL file and load the updated
        // commit tree
        *wal = compact_wal;

        self.force_push(summary).await?;

        // Refresh in-memory vault and mirrored copy
        self.refresh_vault(summary)?;

        Ok((old_size, new_size))
    }

    /// Respond to a change notification.
    pub async fn handle_change(
        &mut self,
        change: ChangeNotification,
    ) -> Result<HashSet<ChangeAction>> {
        // Gather actions corresponding to the events
        let mut actions = HashSet::new();
        for event in change.changes() {
            let action = match event {
                ChangeEvent::DeleteVault => {
                    ChangeAction::Remove(*change.vault_id())
                }
                _ => ChangeAction::Pull(*change.vault_id()),
            };
            actions.insert(action);
        }

        // Consume and react to the actions
        for action in &actions {
            let summary = self
                .state
                .find_vault(&SecretRef::Id(*change.vault_id()))
                .cloned();

            if let Some(summary) = &summary {
                match action {
                    ChangeAction::Pull(_) => {
                        let tree = self
                            .wal_tree(summary)
                            .ok_or(sos_core::Error::NoRootCommit)?;

                        let head = tree.head()?;

                        tracing::debug!(
                            vault_id = ?summary.id(),
                            change_root = ?change.proof().root_hex(),
                            root = ?head.root_hex(),
                            "handle_change");

                        // Looks like the change was made elsewhere
                        // and we should attempt to sync with the server
                        if change.proof().root() != head.root() {
                            let (status, _) =
                                self.vault_status(summary).await?;
                            match status {
                                SyncStatus::Behind(_, _) => {
                                    self.pull(summary, false).await?;
                                }
                                SyncStatus::Diverged(_) => {
                                    if let Some(_) = change
                                        .changes()
                                        .into_iter()
                                        .find(|c| {
                                            *c == &ChangeEvent::UpdateVault
                                        })
                                    {
                                        // If the trees have diverged and the other
                                        // node indicated it did an update to the
                                        // entire vault then we need a force pull to
                                        // stay in sync
                                        self.pull(summary, true).await?;
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    ChangeAction::Remove(_) => {
                        self.remove_local_cache(summary)?;
                    }
                }
            }
        }

        Ok(actions)
    }

    /// Load the vault summaries from a remote node.
    pub async fn load_vaults(&mut self) -> Result<&[Summary]> {
        let summaries = self.client.list_vaults().await?;

        self.load_caches(&summaries)?;

        self.state.set_summaries(summaries);

        Ok(self.vaults())
    }

    /// Get the state for this node cache.
    pub fn state(&self) -> &NodeState {
        &self.state
    }

    /// Create a new account and default login vault.
    pub async fn create_account(
        &mut self,
        name: Option<String>,
    ) -> Result<(SecretString, Summary)> {
        self.create(name, None, true).await
    }

    /// Create a new vault.
    pub async fn create_vault(
        &mut self,
        name: String,
        passphrase: Option<String>,
    ) -> Result<(SecretString, Summary)> {
        self.create(Some(name), passphrase, false).await
    }

    /// Remove a vault.
    pub async fn remove_vault(&mut self, summary: &Summary) -> Result<()> {
        // Attempt to delete on the remote server
        let (status, _) = self.client.delete_vault(summary.id()).await?;
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        // Remove local state
        self.remove_local_cache(summary)?;

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

    /// Attempt to set the vault name on the remote node.
    pub async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<()> {
        let event = SyncEvent::SetVaultName(Cow::Borrowed(name));
        let status = self.patch_wal(summary, vec![event]).await?;
        if status.is_success() {
            for item in self.state.summaries_mut().iter_mut() {
                if item.id() == summary.id() {
                    item.set_name(name.to_string());
                }
            }
            Ok(())
        } else {
            Err(Error::ResponseCode(status.into()))
        }
    }

    /// Get a comparison between a local WAL and remote WAL.
    ///
    /// If a patch file has unsaved events then the number
    /// of pending events is returned along with the `SyncStatus`.
    pub async fn vault_status(
        &self,
        summary: &Summary,
    ) -> Result<(SyncStatus, Option<usize>)> {
        let (wal, patch_file) = self
            .cache
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let client_proof = wal.tree().head()?;
        let (status, server_proof, match_proof) = self
            .client
            .status(summary.id(), Some(client_proof.clone()))
            .await?;
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        let equals = client_proof.root() == server_proof.root();

        let pair = CommitPair {
            local: client_proof,
            remote: server_proof.clone(),
        };

        let status = if equals {
            SyncStatus::Equal(pair)
        } else {
            if let Some(_) = match_proof {
                let (diff, _) =
                    pair.remote.len().overflowing_sub(pair.local.len());
                SyncStatus::Behind(pair, diff)
            } else {
                let comparison = wal.tree().compare(server_proof)?;
                let is_ahead = match comparison {
                    Comparison::Contains(_, _) => true,
                    _ => false,
                };

                if is_ahead {
                    let (diff, _) =
                        pair.local.len().overflowing_sub(pair.remote.len());
                    SyncStatus::Ahead(pair, diff)
                } else {
                    SyncStatus::Diverged(pair)
                }
            }
        };

        let pending_events = if patch_file.has_events()? {
            Some(patch_file.count_events()?)
        } else {
            None
        };

        Ok((status, pending_events))
    }

    /// Update an existing vault.
    pub async fn update_vault<'a>(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<WalEvent<'a>>,
    ) -> Result<()> {
        let (wal, _) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        // Send the new vault to the server
        let buffer = encode(vault)?;
        let (status, server_proof) =
            self.client.save_vault(summary.id(), buffer).await?;
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        let server_proof = server_proof.ok_or(Error::ServerProof)?;

        // Apply the new WAL events to our local WAL log
        wal.clear()?;
        wal.apply(events, Some(CommitHash(*server_proof.root())))?;

        // Refresh the in-memory and disc-based mirror
        self.refresh_vault(summary)?;

        Ok(())
    }

    /// Load a vault, unlock it and set it as the current vault.
    pub async fn open_vault(
        &mut self,
        summary: &Summary,
        passphrase: &str,
    ) -> Result<()> {
        let vault = self.get_wal_vault(summary).await?;
        let vault_path = if self.mirror {
            let vault_path = self.vault_path(summary);
            if !vault_path.exists() {
                let buffer = encode(&vault)?;
                self.write_vault_mirror(summary, &buffer)?;
            }
            Some(vault_path)
        } else {
            None
        };

        self.state.open_vault(passphrase, vault, vault_path)?;
        Ok(())
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

    /// Apply changes to a vault.
    pub async fn patch_vault(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'_>>,
    ) -> Result<()> {
        let status = self.patch_wal(summary, events).await?;

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;
        Ok(())
    }

    /// Get a reference to the commit tree for a WAL file.
    pub fn wal_tree(&self, summary: &Summary) -> Option<&CommitTree> {
        self.cache.get(summary.id()).map(|(wal, _)| wal.tree())
    }

    /// Download changes from the remote server.
    pub async fn pull(
        &mut self,
        summary: &Summary,
        force: bool,
    ) -> Result<SyncInfo> {
        let (wal, _) = self
            .cache
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let client_proof = wal.tree().head()?;

        let (status, server_proof, match_proof) = self
            .client
            .status(summary.id(), Some(client_proof.clone()))
            .await?;
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        let equals = client_proof.root() == server_proof.root();
        let can_pull_safely = match_proof.is_some();
        let status = if force {
            SyncKind::Force
        } else if equals {
            SyncKind::Equal
        } else if can_pull_safely {
            SyncKind::Safe
        } else {
            SyncKind::Unsafe
        };

        let mut info = SyncInfo {
            before: (client_proof, server_proof),
            after: None,
            status,
        };

        if force || !equals {
            if force || can_pull_safely {
                let result_proof = self.force_pull(summary).await?;
                info.after = Some(result_proof);

                // If we have unsaved staged events try to apply them
                self.apply_patch_file(summary).await?;

                Ok(info)
            } else {
                Ok(info)
            }
        } else {
            Ok(info)
        }
    }

    /// Upload changes to the remote server.
    pub async fn push(
        &mut self,
        summary: &Summary,
        force: bool,
    ) -> Result<SyncInfo> {
        let (wal, _) = self
            .cache
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let client_proof = wal.tree().head()?;

        let (status, server_proof, _match_proof) =
            self.client.status(summary.id(), None).await?;
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        let equals = client_proof.root() == server_proof.root();

        let comparison = wal.tree().compare(server_proof.clone())?;
        let can_push_safely = match comparison {
            Comparison::Contains(_, _) => true,
            _ => false,
        };

        let status = if force {
            SyncKind::Force
        } else if equals {
            SyncKind::Equal
        } else if can_push_safely {
            SyncKind::Safe
        } else {
            SyncKind::Unsafe
        };

        let mut info = SyncInfo {
            before: (client_proof, server_proof),
            after: None,
            status,
        };

        if force || !equals {
            if force || can_push_safely {
                let result_proof = self.force_push(summary).await?;
                info.after = Some(result_proof);

                // If we have unsaved staged events try to apply them
                self.apply_patch_file(summary).await?;

                Ok(info)
            } else {
                Ok(info)
            }
        } else {
            Ok(info)
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl NodeCache<WalFile, PatchFile> {
    /// Create new node cache backed by files on disc.
    pub fn new_file_cache<D: AsRef<Path>>(
        server: Url,
        cache_dir: D,
        signer: BoxedSigner,
    ) -> Result<NodeCache<WalFile, PatchFile>> {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        if !cache_dir.is_dir() {
            return Err(Error::NotDirectory(cache_dir));
        }

        let address = signer.address()?;
        let address = format!("{}", address);
        let user_dir = cache_dir.join(&address);
        std::fs::create_dir_all(&user_dir)?;

        let snapshots = Some(SnapShotManager::new(&user_dir)?);
        let client = RpcClient::new(server, signer);

        Ok(Self {
            state: Default::default(),
            client,
            user_dir: Some(user_dir),
            cache: Default::default(),
            mirror: true,
            snapshots,
        })
    }
}

impl NodeCache<WalMemory, PatchMemory<'static>> {
    /// Create new node cache backed by memory.
    pub fn new_memory_cache(
        server: Url,
        signer: BoxedSigner,
    ) -> NodeCache<WalMemory, PatchMemory<'static>> {
        let client = RpcClient::new(server, signer);
        Self {
            state: Default::default(),
            client,
            user_dir: None,
            cache: Default::default(),
            mirror: false,
            snapshots: None,
        }
    }
}

impl<W, P> NodeCache<W, P>
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
        let (passphrase, vault, buffer) = self.new_vault(name, passphrase)?;
        let summary = vault.summary().clone();

        if self.mirror {
            self.write_vault_mirror(&summary, &buffer)?;
        }

        let status = if is_account {
            self.client.create_account(buffer).await?
        } else {
            let (status, _) = self.client.create_vault(buffer).await?;
            status
        };

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        // Add the summary to the vaults we are managing
        self.state.add_summary(summary.clone());

        // Initialize the local cache for WAL and Patch
        self.init_local_cache(&summary, Some(vault))?;

        Ok((passphrase, summary))
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn write_vault_mirror(
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
    fn write_vault_mirror(
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

    /// Fetch the remote WAL file.
    async fn pull_wal(&mut self, summary: &Summary) -> Result<CommitProof> {
        let _cached_wal_path = self.wal_path(summary);
        let wal = self
            .cache
            .get_mut(summary.id())
            .map(|(w, _)| w)
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        let client_proof = if let Some(_) = wal.tree().root() {
            let proof = wal.tree().head()?;
            tracing::debug!(root = %proof.root_hex(), "pull_wal wants diff");
            Some(proof)
        } else {
            None
        };

        let (status, server_proof, buffer) = self
            .client
            .load_wal(summary.id(), client_proof.clone())
            .await?;

        tracing::debug!(status = %status, "pull_wal");

        match status {
            StatusCode::OK => {
                let buffer = buffer.unwrap();
                let server_proof = server_proof.ok_or(Error::ServerProof)?;
                tracing::debug!(
                    server_root_hash = %server_proof.root_hex(), "pull_wal");

                let client_proof = match client_proof {
                    // If we sent a proof to the server then we
                    // are expecting a diff of records
                    Some(_proof) => {
                        tracing::debug!(bytes = ?buffer.len(),
                            "pull_wal write diff WAL records");

                        // Check the identity looks good
                        FileIdentity::read_slice(&buffer, &WAL_IDENTITY)?;

                        // Append the diff bytes
                        wal.append_buffer(buffer)?;

                        wal.tree().head()?
                    }
                    // Otherwise the server should send us the entire
                    // WAL file
                    None => {
                        tracing::debug!(bytes = ?buffer.len(),
                            "pull_wal write entire WAL");

                        // Check the identity looks good
                        FileIdentity::read_slice(&buffer, &WAL_IDENTITY)?;
                        wal.write_buffer(buffer)?;
                        wal.tree().head()?
                    }
                };

                assert_proofs_eq(&client_proof, &server_proof)?;

                Ok(client_proof)
            }
            StatusCode::NOT_MODIFIED => {
                // Verify that both proofs are equal
                let (wal, _) = self
                    .cache
                    .get(summary.id())
                    .ok_or(Error::CacheNotAvailable(*summary.id()))?;
                let server_proof = server_proof.ok_or(Error::ServerProof)?;
                let client_proof = wal.tree().head()?;
                assert_proofs_eq(&client_proof, &server_proof)?;
                Ok(client_proof)
            }
            StatusCode::CONFLICT => {
                // If we are expecting a diff but got a conflict
                // from the server then the trees have diverged.
                //
                // We should pull from the server a complete fresh
                // tree at this point so we can get back in sync
                // however we need confirmation that this is allowed
                // from the user.
                if let Some(client_proof) = client_proof {
                    let server_proof =
                        server_proof.ok_or(Error::ServerProof)?;
                    Err(Error::Conflict {
                        summary: summary.clone(),
                        local: client_proof.reduce(),
                        remote: server_proof.reduce(),
                    })
                } else {
                    Err(Error::ResponseCode(status.into()))
                }
            }
            _ => Err(Error::ResponseCode(status.into())),
        }
    }

    /// Load a vault by attempting to fetch the WAL file and caching
    /// the result on disc then building an in-memory vault from the WAL.
    async fn get_wal_vault(&mut self, summary: &Summary) -> Result<Vault> {
        // Fetch latest version of the WAL content
        self.pull_wal(summary).await?;

        // Reduce the WAL to a vault
        let wal = self
            .cache
            .get_mut(summary.id())
            .map(|(w, _)| w)
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let vault = WalReducer::new().reduce(wal)?.build()?;
        Ok(vault)
    }

    /// Attempt to patch a remote WAL file.
    #[cfg_attr(target_arch="wasm32", async_recursion(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_recursion)]
    async fn patch_wal(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'async_recursion>>,
    ) -> Result<StatusCode> {
        let (wal, patch_file) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        let patch = patch_file.append(events)?;

        let client_proof = wal.tree().head()?;

        let (status, server_proof, match_proof) = self
            .client
            .apply_patch(
                *summary.id(),
                client_proof.clone(),
                patch.clone().into_owned(),
            )
            .await?;

        match status {
            StatusCode::OK => {
                let server_proof = server_proof.ok_or(Error::ServerProof)?;

                // Apply changes to the local WAL file
                let mut changes = Vec::new();
                for event in patch.0 {
                    if let Ok::<WalEvent<'_>, sos_core::Error>(wal_event) =
                        event.try_into()
                    {
                        changes.push(wal_event);
                    }
                }

                // Pass the expected root hash so changes are reverted
                // if the root hashes do not match
                wal.apply(changes, Some(CommitHash(server_proof.0)))?;

                patch_file.truncate()?;

                let client_proof = wal.tree().head()?;
                assert_proofs_eq(&client_proof, &server_proof)?;
                Ok(status)
            }
            StatusCode::CONFLICT => {
                let server_proof = server_proof.ok_or(Error::ServerProof)?;

                // Server replied with a proof that they have a
                // leaf node corresponding to our root hash which
                // indicates that we are behind the remote so we
                // can try to pull again and try to patch afterwards
                if let Some(_) = match_proof {
                    tracing::debug!(
                        client_root = %client_proof.root_hex(),
                        server_root = %server_proof.root_hex(),
                        "conflict on patch, attempting sync");

                    // Pull the WAL from the server that we
                    // are behind
                    self.pull_wal(summary).await?;

                    tracing::debug!(vault_id = %summary.id(),
                        "conflict on patch, pulled remote WAL");

                    // Retry sending our local changes to
                    // the remote WAL
                    let status =
                        self.patch_wal(summary, patch.0.clone()).await?;

                    tracing::debug!(status = %status,
                        "conflict on patch, retry patch status");

                    if status.is_success() {
                        // If the retry was successful then
                        // we should update the in-memory vault
                        // so if reflects the pulled changes
                        // with our patch applied over the top
                        let updated_vault =
                            self.get_wal_vault(summary).await?;

                        if let Some(keeper) = self.current_mut() {
                            if keeper.id() == summary.id() {
                                let existing_vault = keeper.vault_mut();
                                *existing_vault = updated_vault;
                            }
                        }
                    }

                    Ok(status)
                } else {
                    Err(Error::Conflict {
                        summary: summary.clone(),
                        local: client_proof.reduce(),
                        remote: server_proof.reduce(),
                    })
                }
            }
            _ => Err(Error::ResponseCode(status.into())),
        }
    }

    // Refresh the in-memory vault of the current selection
    // from the contents of the current WAL file.
    fn refresh_vault(&mut self, summary: &Summary) -> Result<()> {
        let wal = self
            .cache
            .get_mut(summary.id())
            .map(|(w, _)| w)
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let vault = WalReducer::new().reduce(wal)?.build()?;

        let mirror = self.mirror;
        let _vault_path = self.vault_path(summary);

        // Rewrite the on-disc version if we are mirroring
        if mirror {
            let buffer = encode(&vault)?;
            self.write_vault_mirror(summary, &buffer)?;
        }

        if let Some(keeper) = self.current_mut() {
            if keeper.id() == summary.id() {
                // Update the in-memory version
                let keeper_vault = keeper.vault_mut();
                *keeper_vault = vault;
            }
        }
        Ok(())
    }

    async fn force_pull(&mut self, summary: &Summary) -> Result<CommitProof> {
        // Move our cached vault to a backup
        let vault_path = self.vault_path(summary);

        #[cfg(not(target_arch = "wasm32"))]
        if vault_path.exists() {
            let mut vault_backup = vault_path.clone();
            vault_backup.set_extension(VAULT_BACKUP_EXT);
            std::fs::rename(&vault_path, &vault_backup)?;
            tracing::debug!(
                vault = ?vault_path, backup = ?vault_backup, "vault backup");
        }

        let (wal, _) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        // Create a snapshot of the WAL before deleting it
        if let Some(snapshots) = &self.snapshots {
            let root_hash = wal.tree().root().ok_or(Error::NoRootCommit)?;
            let (snapshot, _) =
                snapshots.create(summary.id(), wal.path(), root_hash)?;
            tracing::debug!(
                path = ?snapshot.0, "force_pull snapshot");
        }

        // Remove the existing WAL file
        #[cfg(not(target_arch = "wasm32"))]
        std::fs::remove_file(wal.path())?;

        // Need to recreate the WAL file correctly before pulling
        // as pull_wal() expects the file to exist
        *wal = W::new(wal.path())?;
        wal.load_tree()?;

        // Pull the remote WAL
        self.pull_wal(summary).await?;

        let (wal, _) = self
            .cache
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        let proof = wal.tree().head()?;

        self.refresh_vault(summary)?;

        Ok(proof)
    }

    async fn force_push(&mut self, summary: &Summary) -> Result<CommitProof> {
        // TODO: load any unsaved events from the patch file and
        // TODO: apply them to the WAL!

        let (wal, _) = self
            .cache
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let client_proof = wal.tree().head()?;
        let body = std::fs::read(wal.path())?;
        let (status, server_proof) = self
            .client
            .save_wal(summary.id(), client_proof.clone(), body)
            .await?;

        let server_proof = server_proof.ok_or(Error::ServerProof)?;
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        assert_proofs_eq(&client_proof, &server_proof)?;
        Ok(client_proof)
    }

    /// Attempt to drain the patch file and apply events to
    /// the remote server.
    async fn apply_patch_file(&mut self, summary: &Summary) -> Result<()> {
        let (_, patch_file) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        let has_events = patch_file.has_events()?;

        tracing::debug!(has_events, "apply patch file");

        // Got some events which haven't been saved so try
        // to apply them over the top of the new WAL
        if has_events {
            // Must drain() the patch file as calling
            // patch_vault() will append them again in
            // case of failure
            let patch = patch_file.drain()?;
            let events = patch.0;

            tracing::debug!(events = events.len(), "apply patch file events");

            self.patch_vault(summary, events).await?;
            Ok(())
        } else {
            Ok(())
        }
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
