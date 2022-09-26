//! Wrapper for the RPC client that handles authentication
//! and retries when an unauthorized response is returned.
use super::{Error, Result};
use crate::client::net::{MaybeRetry, RpcClient};

use async_recursion::async_recursion;
use async_trait::async_trait;
use http::StatusCode;
use secrecy::{ExposeSecret, SecretString};
use sos_core::{
    commit_tree::{CommitPair, CommitProof, Comparison},
    constants::WAL_IDENTITY,
    encode,
    events::{
        ChangeAction, ChangeEvent, ChangeNotification, SyncEvent, WalEvent,
    },
    secret::SecretRef,
    signer::BoxedSigner,
    vault::{Summary, Vault, VaultId},
    wal::{
        memory::WalMemory,
        snapshot::{SnapShot, SnapShotManager},
        WalProvider,
    },
    ChangePassword, CommitHash, FileIdentity, PatchMemory, PatchProvider,
};

#[cfg(not(target_arch = "wasm32"))]
use sos_core::{wal::file::WalFile, PatchFile};

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    path::PathBuf,
};
use uuid::Uuid;

use crate::{
    client::provider::{fs_adapter, ProviderState, StorageDirs, StorageProvider},
    retry,
    sync::{SyncInfo, SyncKind, SyncStatus},
};

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

#[deprecated(note = "Use the version in local_storage.")]
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

/// Local data cache for a node.
///
/// May be backed by files on disc or in-memory implementations
/// for use in webassembly.
pub struct RemoteProvider<W, P> {
    /// State of this node.
    state: ProviderState,

    /// Client to use for server communication.
    client: RpcClient,

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

        //let user_dir = ensure_user_vaults_dir(cache_dir, &signer)?;

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
        let status = self.patch_wal(summary, events).await?;
        status
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(status.into()))?;
        Ok(())
    }

    async fn set_vault_name(
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
        self.force_push(summary).await?;
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
        self.pull_wal(summary).await?;
        StorageProvider::<W, P>::get_wal_vault(self, summary).await
    }
}

impl<W, P> RemoteProvider<W, P>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    /// Get the snapshot manager for this cache.
    pub fn snapshots(&self) -> Option<&SnapShotManager> {
        self.snapshots.as_ref()
    }

    /// Get the client.
    pub fn client(&self) -> &RpcClient {
        &self.client
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

    /// Get a comparison between a local WAL and remote WAL.
    ///
    /// If a patch file has unsaved events then the number
    /// of pending events is returned along with the `SyncStatus`.
    pub async fn vault_status(
        &mut self,
        summary: &Summary,
    ) -> Result<(SyncStatus, Option<usize>)> {
        let (wal, patch_file) = self
            .cache
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;
        let client_proof = wal.tree().head()?;
        let (status, (server_proof, match_proof)) = retry!(
            || self.client.status(summary.id(), Some(client_proof.clone())),
            &mut self.client
        );
        //.await?;
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

        let (status, (server_proof, match_proof)) = retry!(
            || self.client.status(summary.id(), Some(client_proof.clone())),
            &mut self.client
        );
        //.await?;
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

        let (status, (server_proof, _match_proof)) = retry!(
            || self.client.status(summary.id(), None),
            &mut self.client
        );
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

        let (status, (server_proof, buffer)) = retry!(
            || self.client.load_wal(summary.id(), client_proof.clone()),
            &mut self.client
        );

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

        let (status, (server_proof, match_proof)) = retry!(
            || self.client.apply_patch(
                *summary.id(),
                client_proof.clone(),
                patch.clone().into_owned(),
            ),
            &mut self.client
        );

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

    async fn force_pull(&mut self, summary: &Summary) -> Result<CommitProof> {
        // Noop on wasm32
        self.backup_vault_file(summary).await?;

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

        // Noop on wasm32
        fs_adapter::remove_file(wal.path()).await?;

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

        self.refresh_vault(summary, None)?;

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
        let (status, server_proof) = retry!(
            || self.client.save_wal(
                summary.id(),
                client_proof.clone(),
                body.clone()
            ),
            &mut self.client
        );

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
}
