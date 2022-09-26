//! Wrapper for the RPC client that handles authentication
//! and retries when an unauthorized response is returned.
use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use async_trait::async_trait;
use http::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use sos_core::{
    encode,
    events::{
        ChangeAction, ChangeEvent, ChangeNotification, SyncEvent, WalEvent,
    },
    secret::SecretRef,
    vault::{Summary, Vault, VaultId},
    wal::{memory::WalMemory, snapshot::SnapShotManager, WalProvider},
    ChangePassword, CommitHash, PatchMemory, PatchProvider,
};

#[cfg(not(target_arch = "wasm32"))]
use sos_core::{wal::file::WalFile, PatchFile};

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
};
use uuid::Uuid;

use crate::{
    client::provider::{
        fs_adapter, sync, ProviderState, StorageDirs, StorageProvider,
    },
    retry,
    sync::{SyncInfo, SyncStatus},
};

/// Local data cache for a node.
///
/// May be backed by files on disc or in-memory implementations
/// for use in webassembly.
pub struct RemoteProvider<W, P> {
    /// State of this node.
    state: ProviderState,

    /// Directories for file storage.
    ///
    /// For memory based storage the paths will be empty.
    dirs: StorageDirs,

    /// Data for the cache.
    cache: HashMap<Uuid, (W, P)>,

    /// Snapshots manager for WAL files.
    ///
    /// Only available when using disc backing storage.
    snapshots: Option<SnapShotManager>,

    /// Client to use for remote communication.
    client: RpcClient,
}

#[cfg(not(target_arch = "wasm32"))]
impl RemoteProvider<WalFile, PatchFile> {
    /// Create new node cache backed by files on disc.
    pub fn new_file_cache<D: AsRef<Path>>(
        client: RpcClient,
        dirs: StorageDirs,
    ) -> Result<RemoteProvider<WalFile, PatchFile>> {
        if !dirs.documents_dir().is_dir() {
            return Err(Error::NotDirectory(
                dirs.documents_dir().to_path_buf(),
            ));
        }

        let snapshots = Some(SnapShotManager::new(dirs.user_dir())?);
        Ok(Self {
            state: ProviderState::new(false),
            cache: Default::default(),
            client,
            dirs,
            snapshots,
        })
    }
}

impl RemoteProvider<WalMemory, PatchMemory<'static>> {
    /// Create new node cache backed by memory.
    pub fn new_memory_cache(
        client: RpcClient,
    ) -> RemoteProvider<WalMemory, PatchMemory<'static>> {
        Self {
            state: ProviderState::new(false),
            cache: Default::default(),
            dirs: Default::default(),
            client,
            snapshots: None,
        }
    }
}

#[async_trait]
impl<W, P> StorageProvider<W, P> for RemoteProvider<W, P>
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

    async fn authenticate(&mut self) -> Result<()> {
        Ok(self.client.authenticate().await?)
    }

    async fn load_vaults(&mut self) -> Result<&[Summary]> {
        let (_, summaries) =
            retry!(|| self.client.list_vaults(), &mut self.client);

        self.load_caches(&summaries)?;
        self.state.set_summaries(summaries);
        Ok(self.vaults())
    }

    async fn patch_vault(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'_>>,
    ) -> Result<()> {
        let (wal_file, patch_file) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        sync::patch(&mut self.client, summary, wal_file, patch_file, events)
            .await
    }

    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<()> {
        let event = SyncEvent::SetVaultName(Cow::Borrowed(name));

        let (wal_file, patch_file) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        let status = sync::apply_patch(
            &mut self.client,
            summary,
            wal_file,
            patch_file,
            vec![event],
        )
        .await?;

        //let status = self.apply_patch(summary, vec![event]).await?;
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

    async fn remove_vault(&mut self, summary: &Summary) -> Result<()> {
        // Attempt to delete on the remote server
        let (status, _) = retry!(
            || self.client.delete_vault(summary.id()),
            &mut self.client
        );
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        // Remove local state
        self.remove_local_cache(summary).await?;
        Ok(())
    }

    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        let (old_size, new_size) =
            StorageProvider::<W, P>::compact(self, summary).await?;
        self.push(summary, true).await?;
        Ok((old_size, new_size))
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
        self.refresh_vault(vault.summary(), Some(&new_passphrase))?;

        if let Some(keeper) = self.current_mut() {
            if keeper.summary().id() == vault.summary().id() {
                keeper.unlock(new_passphrase.expose_secret())?;
            }
        }

        Ok(new_passphrase)
    }

    async fn get_wal_vault(&mut self, summary: &Summary) -> Result<Vault> {
        // Fetch latest version of the WAL content
        self.pull(summary, false).await?;
        StorageProvider::<W, P>::get_wal_vault(self, summary).await
    }

    async fn pull(
        &mut self,
        summary: &Summary,
        force: bool,
    ) -> Result<SyncInfo> {
        if force {
            // Noop on wasm32
            self.backup_vault_file(summary).await?;
        }

        let (wal_file, patch_file) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        if force {
            // Create a snapshot of the WAL before deleting it
            if let Some(snapshots) = &self.snapshots {
                let root_hash =
                    wal_file.tree().root().ok_or(Error::NoRootCommit)?;
                let (snapshot, _) = snapshots.create(
                    summary.id(),
                    wal_file.path(),
                    root_hash,
                )?;
                tracing::debug!(
                    path = ?snapshot.0, "force_pull snapshot");
            }
            // Noop on wasm32
            fs_adapter::remove_file(wal_file.path()).await?;
        }

        sync::pull(&mut self.client, summary, wal_file, patch_file, force)
            .await
    }

    async fn push(
        &mut self,
        summary: &Summary,
        force: bool,
    ) -> Result<SyncInfo> {
        let (wal_file, patch_file) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        sync::push(&mut self.client, summary, wal_file, patch_file, force)
            .await
    }

    /// Get a comparison between a local WAL and remote WAL.
    ///
    /// If a patch file has unsaved events then the number
    /// of pending events is returned along with the `SyncStatus`.
    async fn status(
        &mut self,
        summary: &Summary,
    ) -> Result<(SyncStatus, Option<usize>)> {
        let (wal_file, patch_file) = self
            .cache
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        sync::status(&mut self.client, summary, wal_file, patch_file).await
    }
}

impl<W, P> RemoteProvider<W, P>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    /// Get the client.
    pub fn client(&self) -> &RpcClient {
        &self.client
    }

    /// Respond to a change notification.
    ///
    /// The return flag indicates whether the change was made
    /// by this node which is determined by comparing the session
    /// identifier on the change notification with the current
    /// session identifier for this node.
    pub async fn handle_change(
        &mut self,
        change: ChangeNotification,
    ) -> Result<(bool, HashSet<ChangeAction>)> {
        // Gather actions corresponding to the events
        let mut actions = HashSet::new();
        for event in change.changes() {
            let action = match event {
                ChangeEvent::CreateVault(summary) => {
                    ChangeAction::Create(summary.clone())
                }
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
                            .commit_tree(summary)
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
                            let (status, _) = self.status(summary).await?;
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
                        self.remove_local_cache(summary).await?;
                    }
                    _ => {}
                }
            } else {
                match action {
                    ChangeAction::Create(summary) => {
                        self.add_local_cache(summary.clone())?;
                    }
                    _ => {}
                }
            }
        }

        // Was this change notification triggered by us?
        let self_change = match self.client.session_id() {
            Ok(id) => &id == change.session_id(),
            // Maybe the session is no longer available
            Err(_) => false,
        };

        Ok((self_change, actions))
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
        let current_id = self.current().map(|c| c.id().clone());

        // If the deleted vault is the currently selected
        // vault we must close it
        if let Some(id) = &current_id {
            if id == summary.id() {
                self.close_vault();
            }
        }

        // Remove a mirrored vault file if it exists
        self.remove_vault_file(summary).await?;

        // Remove from our cache of managed vaults
        self.cache.remove(summary.id());

        // Remove from the state of managed vaults
        self.state.remove_summary(summary);

        Ok(())
    }

    /// Update an existing vault by saving the new vault
    /// on a remote node.
    async fn update_vault<'a>(
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
        let (status, server_proof) = retry!(
            || self.client.save_vault(summary.id(), buffer.clone()),
            &mut self.client
        );
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        let server_proof = server_proof.ok_or(Error::ServerProof)?;

        // Apply the new WAL events to our local WAL log
        wal.clear()?;
        wal.apply(events, Some(CommitHash(*server_proof.root())))?;

        Ok(())
    }

    /// Create a new account or vault.
    async fn create(
        &mut self,
        name: Option<String>,
        passphrase: Option<String>,
        is_account: bool,
    ) -> Result<(SecretString, Summary)> {
        let (passphrase, vault, buffer) =
            Vault::new_buffer(name, passphrase)?;
        let summary = vault.summary().clone();

        if self.state().mirror() {
            self.write_vault_file(&summary, &buffer)?;
        }

        let status = if is_account {
            let (status, _) = retry!(
                || self.client.create_account(buffer.clone()),
                &mut self.client
            );
            status
        } else {
            let (status, _) = retry!(
                || self.client.create_vault(buffer.clone()),
                &mut self.client
            );
            status
        };

        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;

        // Add the summary to the vaults we are managing
        self.state.add_summary(summary.clone());

        // Initialize the local cache for WAL and Patch
        self.create_cache_entry(&summary, Some(vault))?;

        Ok((passphrase, summary))
    }
}
