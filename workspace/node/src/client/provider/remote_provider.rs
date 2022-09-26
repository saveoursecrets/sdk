//! Wrapper for the RPC client that handles authentication
//! and retries when an unauthorized response is returned.
use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use async_trait::async_trait;
use http::StatusCode;
use secrecy::SecretString;
use sos_core::{
    encode,
    events::{ChangeAction, ChangeNotification, SyncEvent, WalEvent},
    vault::{Summary, Vault, VaultId},
    wal::{memory::WalMemory, snapshot::SnapShotManager, WalProvider},
    CommitHash, PatchMemory, PatchProvider,
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

    async fn create_vault_or_account(
        &mut self,
        name: Option<String>,
        passphrase: Option<String>,
        is_account: bool,
    ) -> Result<(SecretString, Summary)> {
        let (passphrase, vault, buffer) =
            Vault::new_buffer(name, passphrase)?;
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

        // Remove the files
        self.remove_vault_file(summary).await?;

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

    async fn handle_change(
        &mut self,
        change: ChangeNotification,
    ) -> Result<(bool, HashSet<ChangeAction>)> {
        // Was this change notification triggered by us?
        let self_change = match self.client.session_id() {
            Ok(id) => &id == change.session_id(),
            // Maybe the session is no longer available
            Err(_) => false,
        };
        let actions = sync::handle_change(self, change).await?;
        Ok((self_change, actions))
    }
}
