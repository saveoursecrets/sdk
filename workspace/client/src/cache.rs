//! Cache of local WAL files.
use crate::{
    client::{decode_match_proof, Client},
    Conflict, Error, Result,
};
use async_recursion::async_recursion;
use async_trait::async_trait;
use reqwest::{Response, StatusCode};
use sos_core::{
    address::AddressStr,
    commit_tree::{wal_commit_tree, CommitProof, CommitTree},
    constants::{VAULT_BACKUP_EXT, WAL_DELETED_EXT, WAL_IDENTITY},
    encode,
    events::{PatchFile, SyncEvent, WalEvent},
    generate_passphrase,
    secret::SecretRef,
    vault::{Summary, Vault},
    wal::{
        file::WalFile,
        reducer::WalReducer,
        snapshot::{SnapShot, SnapShotManager},
        WalProvider,
    },
    CommitHash, FileIdentity, Gatekeeper, VaultFileAccess,
};
use std::{
    borrow::Cow,
    collections::HashMap,
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use url::Url;
use uuid::Uuid;

fn assert_proofs_eq(
    client_proof: CommitProof,
    server_proof: CommitProof,
) -> Result<()> {
    if client_proof.0 != server_proof.0 {
        let client = CommitHash(client_proof.0);
        let server = CommitHash(server_proof.0);
        Err(Error::RootHashMismatch(client, server))
    } else {
        Ok(())
    }
}

/// Trait for types that cache vaults locally; support a *current* view
/// into a selected vault and allow making changes to the currently
/// selected vault.
#[async_trait]
pub trait ClientCache {
    /// Get the server URL.
    fn server(&self) -> &Url;

    /// Get the address of the current user.
    fn address(&self) -> Result<AddressStr>;

    /// Get the vault summaries for this cache.
    fn vaults(&self) -> &[Summary];

    /// Get the snapshot manager for this cache.
    fn snapshots(&self) -> &SnapShotManager;

    /// Take a snapshot of the WAL for the given vault.
    fn take_snapshot(&self, summary: &Summary) -> Result<(SnapShot, bool)>;

    /// Compact a WAL file.
    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)>;

    /// Load the vault summaries from the remote server.
    async fn load_vaults(&mut self) -> Result<&[Summary]>;

    /// Attempt to find a summary in this cache.
    fn find_vault(&self, vault: &SecretRef) -> Option<&Summary>;

    /// Create a new account and default login vault.
    async fn create_account(
        &mut self,
        name: Option<String>,
    ) -> Result<String>;

    /// Create a new vault.
    async fn create_vault(&mut self, name: String) -> Result<String>;

    /// Remove a vault.
    async fn remove_vault(&mut self, summary: &Summary) -> Result<()>;

    /// Attempt to set the vault name on the remote server.
    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<()>;

    /// Get a comparison between a local WAL and remote WAL.
    async fn vault_status(
        &self,
        summary: &Summary,
    ) -> Result<(CommitProof, CommitProof)>;

    /// Apply changes to a vault.
    async fn patch_vault(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'_>>,
    ) -> Result<()>;

    /// Load a vault, unlock it and set it as the current vault.
    async fn open_vault(
        &mut self,
        summary: &Summary,
        password: &str,
    ) -> Result<()>;

    /// Get the current in-memory vault access.
    fn current(&self) -> Option<&Gatekeeper>;

    /// Get a mutable reference to the current in-memory vault access.
    fn current_mut(&mut self) -> Option<&mut Gatekeeper>;

    /// Close the currently open vault.
    ///
    /// When a vault is open it is locked before being closed.
    ///
    /// If no vault is open this is a noop.
    fn close_vault(&mut self);

    /// Get a reference to the commit tree for a WAL file.
    fn wal_tree(&self, summary: &Summary) -> Option<&CommitTree>;

    /// Force a pull of the remote WAL regardless of the state of
    /// the local WAL.
    async fn force_pull(&mut self, summary: &Summary) -> Result<()>;

    /// Force a push of the local WAL regardless of the state of
    /// the remote WAL.
    async fn force_push(&mut self, summary: &Summary) -> Result<()>;
}

/// Implements client-side caching of WAL files.
pub struct Cache {
    /// Vaults managed by this cache.
    summaries: Vec<Summary>,
    /// Currently selected in-memory vault.
    current: Option<Gatekeeper>,
    /// Client to use for server communication.
    client: Client,
    /// Directory for the user cache.
    user_dir: PathBuf,
    /// Data for the cache.
    cache: HashMap<Uuid, (WalFile, PatchFile)>,
    /// Mirror WAL files and in-memory contents to vault files
    mirror: bool,
    /// Snapshots of the WAL files.
    snapshots: SnapShotManager,
}

#[async_trait]
impl ClientCache for Cache {
    fn server(&self) -> &Url {
        self.client.server()
    }

    fn address(&self) -> Result<AddressStr> {
        self.client.address()
    }

    fn vaults(&self) -> &[Summary] {
        self.summaries.as_slice()
    }

    fn snapshots(&self) -> &SnapShotManager {
        &self.snapshots
    }

    fn take_snapshot(&self, summary: &Summary) -> Result<(SnapShot, bool)> {
        let (wal, _) = self
            .cache
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(summary.id().clone()))?;
        let root_hash = wal.tree().root().ok_or(Error::NoRootCommit)?;
        Ok(self.snapshots.create(summary.id(), wal.path(), root_hash)?)
    }

    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)> {
        let (wal, _) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(summary.id().clone()))?;

        let old_size = wal.path().metadata()?.len();

        // Get the reduced set of events
        let events = WalReducer::new().reduce(wal)?.compact()?;
        let temp = NamedTempFile::new()?;

        // Apply them to a temporary WAL file
        let mut temp_wal = WalFile::new(temp.path())?;
        temp_wal.apply(events, None)?;

        let new_size = temp_wal.path().metadata()?.len();

        // Remove the existing WAL file
        std::fs::remove_file(wal.path())?;
        // Move the temp file into place
        std::fs::rename(temp.path(), wal.path())?;

        // Need to recreate the WAL file and load the updated
        // commit tree
        *wal = WalFile::new(wal.path())?;
        wal.load_tree()?;

        // Client verifying the new WAL tree
        println!("Verifying new WAL tree");
        let tree = wal_commit_tree(wal.path(), true, |_| {})?;
        println!("AFTER Verifying new WAL tree");

        // Update the server copy of the WAL
        let proof = wal.tree().head()?;
        let body = std::fs::read(wal.path())?;
        let (response, _) =
            self.client.post_wal(summary.id(), &proof, body).await?;
        response
            .status()
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(response.status().into()))?;

        // Refresh in-memory vault and mirrored copy
        self.refresh_vault(summary)?;

        Ok((old_size, new_size))
    }

    async fn load_vaults(&mut self) -> Result<&[Summary]> {
        let summaries = self.client.list_vaults().await?;
        self.load_caches(&summaries)?;
        self.summaries = summaries;
        Ok(self.vaults())
    }

    fn find_vault(&self, vault: &SecretRef) -> Option<&Summary> {
        match vault {
            SecretRef::Name(name) => {
                self.summaries.iter().find(|s| s.name() == name)
            }
            SecretRef::Id(id) => self.summaries.iter().find(|s| s.id() == id),
        }
    }

    async fn create_account(
        &mut self,
        name: Option<String>,
    ) -> Result<String> {
        self.create(name, true).await
    }

    async fn create_vault(&mut self, name: String) -> Result<String> {
        self.create(Some(name), false).await
    }

    async fn remove_vault(&mut self, summary: &Summary) -> Result<()> {
        let current_id = self.current().map(|c| c.id().clone());

        // Attempt to delete on the remote server
        let (response, _) = self.client.delete_wal(summary.id()).await?;
        response
            .status()
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(response.status().into()))?;

        // If the deleted vault is the currently selected
        // vault we must close it
        if let Some(id) = &current_id {
            if id == summary.id() {
                self.close_vault();
            }
        }

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

        // Remove from our cache of managed vaults
        self.cache.remove(summary.id());
        let index =
            self.summaries.iter().position(|s| s.id() == summary.id());
        if let Some(index) = index {
            self.summaries.remove(index);
        }

        Ok(())
    }

    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<()> {
        let event = SyncEvent::SetVaultName(Cow::Borrowed(name));
        let response = self.patch_wal(summary, vec![event]).await?;
        if response.status().is_success() {
            for item in self.summaries.iter_mut() {
                if item.id() == summary.id() {
                    item.set_name(name.to_string());
                }
            }
            Ok(())
        } else {
            Err(Error::ResponseCode(response.status().into()))
        }
    }

    async fn vault_status(
        &self,
        summary: &Summary,
    ) -> Result<(CommitProof, CommitProof)> {
        if let Some((wal, _)) = self.cache.get(summary.id()) {
            let client_proof = wal.tree().head()?;
            let (_response, server_proof) =
                self.client.head_wal(summary.id()).await?;
            Ok((client_proof, server_proof))
        } else {
            Err(Error::CacheNotAvailable(*summary.id()))
        }
    }

    async fn open_vault(
        &mut self,
        summary: &Summary,
        password: &str,
    ) -> Result<()> {
        let vault = self.get_wal_vault(summary).await?;
        let mut keeper = if self.mirror {
            let vault_path = self.vault_path(summary);
            if !vault_path.exists() {
                let buffer = encode(&vault)?;
                let mut file = File::create(&vault_path)?;
                file.write_all(&buffer)?;
            }

            let mirror = Box::new(VaultFileAccess::new(vault_path)?);
            Gatekeeper::new_mirror(vault, mirror)
        } else {
            Gatekeeper::new(vault)
        };
        keeper
            .unlock(password)
            .map_err(|_| Error::VaultUnlockFail)?;
        self.current = Some(keeper);
        Ok(())
    }

    fn current(&self) -> Option<&Gatekeeper> {
        self.current.as_ref()
    }

    fn current_mut(&mut self) -> Option<&mut Gatekeeper> {
        self.current.as_mut()
    }

    async fn patch_vault(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'_>>,
    ) -> Result<()> {
        let response = self.patch_wal(summary, events).await?;
        response
            .status()
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(response.status().into()))?;
        Ok(())
    }

    fn close_vault(&mut self) {
        if let Some(current) = self.current_mut() {
            current.lock();
        }
        self.current = None;
    }

    fn wal_tree(&self, summary: &Summary) -> Option<&CommitTree> {
        self.cache.get(summary.id()).map(|(wal, _)| wal.tree())
    }

    async fn force_pull(&mut self, summary: &Summary) -> Result<()> {
        // Move our cached vault to a backup
        let vault_path = self.vault_path(summary);
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
        let root_hash = wal.tree().root().ok_or(Error::NoRootCommit)?;
        let (snapshot, _) =
            self.snapshots.create(summary.id(), wal.path(), root_hash)?;
        tracing::debug!(
            path = ?snapshot.0, "force_pull snapshot");

        // Remove the existing WAL file
        std::fs::remove_file(wal.path())?;

        // Need to recreate the WAL file correctly before pulling
        // as pull_wal() expects the file to exist
        *wal = WalFile::new(wal.path())?;
        wal.load_tree()?;

        // Pull the remote WAL
        self.pull_wal(summary).await?;

        let (_, patch_file) = self
            .cache
            .get(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        tracing::debug!("force_pull reading from patch file");

        let patch = patch_file.read()?;
        let events = patch.0;

        tracing::debug!(events = events.len(), "force_pull");

        // Got some events which haven't been saved so try
        // to apply them over the top of the new WAL
        if !events.is_empty() {
            self.patch_vault(summary, events).await?;
            self.refresh_vault(summary)?;
        }

        Ok(())
    }

    async fn force_push(&mut self, _summary: &Summary) -> Result<()> {
        todo!("implement a force push")
    }
}

impl Cache {
    /// Create a new cache using the given client and cache directory.
    ///
    /// If the `mirror` option is given then the cache will mirror WAL files
    /// and in-memory content to disc as vault files providing an extra level
    /// if redundancy in case of failure.
    pub fn new<D: AsRef<Path>>(
        client: Client,
        cache_dir: D,
        mirror: bool,
    ) -> Result<Self> {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        if !cache_dir.is_dir() {
            return Err(Error::NotDirectory(cache_dir));
        }

        let address = client.address()?;
        let address = format!("{}", address);
        let user_dir = cache_dir.join(&address);
        std::fs::create_dir_all(&user_dir)?;

        let snapshots = SnapShotManager::new(&user_dir)?;

        Ok(Self {
            summaries: Default::default(),
            current: None,
            client,
            user_dir,
            cache: Default::default(),
            mirror,
            snapshots,
        })
    }

    /// Get the default root directory used for caching client data.
    ///
    /// If the `CACHE_DIR` environment variable is set it is used
    /// instead of the default location.
    pub fn cache_dir() -> Result<PathBuf> {
        let cache_dir = if let Ok(env_cache_dir) = std::env::var("CACHE_DIR")
        {
            let cache_dir = PathBuf::from(env_cache_dir);
            if !cache_dir.is_dir() {
                return Err(Error::NotDirectory(cache_dir));
            }
            cache_dir
        } else {
            let data_local_dir =
                dirs::data_local_dir().ok_or(Error::NoDataLocalDir)?;
            let cache_dir = data_local_dir.join("sos");
            if !cache_dir.exists() {
                std::fs::create_dir(&cache_dir)?;
            }
            cache_dir
        };
        tracing::debug!(cache_dir = ?cache_dir, "cache_dir");
        Ok(cache_dir)
    }

    /// Create a new account or vault.
    async fn create(
        &mut self,
        name: Option<String>,
        is_account: bool,
    ) -> Result<String> {
        let (passphrase, vault, buffer) = self.new_vault(name)?;
        let summary = vault.summary().clone();

        if self.mirror {
            let vault_path = self.vault_path(&summary);
            let mut file = File::create(vault_path)?;
            file.write_all(&buffer)?;
        }

        let response = if is_account {
            self.client.create_account(buffer).await?
        } else {
            let (response, _) = self.client.create_wal(buffer).await?;
            response
        };

        response
            .status()
            .is_success()
            .then_some(())
            .ok_or(Error::ResponseCode(response.status().into()))?;
        self.summaries.push(summary);

        Ok(passphrase)
    }

    fn new_vault(
        &self,
        name: Option<String>,
    ) -> Result<(String, Vault, Vec<u8>)> {
        let (passphrase, _) = generate_passphrase()?;
        let mut vault: Vault = Default::default();
        if let Some(name) = name {
            vault.set_name(name);
        }
        vault.initialize(&passphrase)?;
        let buffer = encode(&vault)?;
        Ok((passphrase, vault, buffer))
    }

    fn load_caches(&mut self, summaries: &[Summary]) -> Result<()> {
        for summary in summaries {
            let patch_path = self.patch_path(summary);
            let patch_file = PatchFile::new(patch_path)?;

            let wal_path = self.wal_path(summary);
            let mut wal_file = WalFile::new(&wal_path)?;
            wal_file.load_tree()?;
            self.cache.insert(*summary.id(), (wal_file, patch_file));
        }
        Ok(())
    }

    fn wal_path(&self, summary: &Summary) -> PathBuf {
        let wal_name = format!("{}.{}", summary.id(), WalFile::extension());
        self.user_dir.join(&wal_name)
    }

    fn vault_path(&self, summary: &Summary) -> PathBuf {
        let wal_name = format!("{}.{}", summary.id(), Vault::extension());
        self.user_dir.join(&wal_name)
    }

    fn patch_path(&self, summary: &Summary) -> PathBuf {
        let patch_name =
            format!("{}.{}", summary.id(), PatchFile::extension());
        self.user_dir.join(&patch_name)
    }

    /// Fetch the remote WAL file.
    async fn pull_wal(&mut self, summary: &Summary) -> Result<()> {
        let cached_wal_path = self.wal_path(summary);
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

        let (response, server_proof) = self
            .client
            .get_wal(summary.id(), client_proof.as_ref())
            .await?;

        let status = response.status();

        tracing::debug!(status = %status, "pull_wal");

        match status {
            StatusCode::OK => {
                if let Some(server_proof) = server_proof {
                    let client_proof = match client_proof {
                        // If we sent a proof to the server then we
                        // are expecting a diff of records
                        Some(_proof) => {
                            let buffer = response.bytes().await?;

                            // Check the identity looks good
                            FileIdentity::read_slice(&buffer, &WAL_IDENTITY)?;

                            // Get buffer of log records after the identity bytes
                            let record_bytes = &buffer[WAL_IDENTITY.len()..];

                            debug_assert!(
                                record_bytes.len() == buffer.len() - 4
                            );

                            // Append the diff bytes without the identity
                            let mut file = OpenOptions::new()
                                .write(true)
                                .append(true)
                                .open(&cached_wal_path)?;
                            file.write_all(record_bytes)?;

                            // Update with the new commit tree
                            wal.load_tree()?;

                            wal.tree().head()?
                        }
                        // Otherwise the server should send us the entire
                        // WAL file
                        None => {
                            // Read in the entire response buffer
                            let buffer = response.bytes().await?;

                            // Check the identity looks good
                            FileIdentity::read_slice(&buffer, &WAL_IDENTITY)?;

                            std::fs::write(&cached_wal_path, &buffer)?;
                            wal.load_tree()?;

                            wal.tree().head()?
                        }
                    };

                    assert_proofs_eq(client_proof, server_proof)?;

                    Ok(())
                } else {
                    Err(Error::ServerProof)
                }
            }
            StatusCode::NOT_MODIFIED => {
                // Verify that both proofs are equal
                if let Some((wal, _)) = self.cache.get(summary.id()) {
                    let server_proof =
                        server_proof.ok_or(Error::ServerProof)?;
                    let client_proof = wal.tree().head()?;
                    assert_proofs_eq(client_proof, server_proof)?;
                    Ok(())
                } else {
                    Err(Error::CacheNotAvailable(*summary.id()))
                }
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
                    Err(Error::Conflict(Conflict {
                        summary: summary.clone(),
                        local: client_proof.reduce(),
                        remote: server_proof.reduce(),
                    }))
                } else {
                    Err(Error::ResponseCode(response.status().into()))
                }
            }
            _ => Err(Error::ResponseCode(response.status().into())),
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
    #[async_recursion]
    async fn patch_wal(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'async_recursion>>,
    ) -> Result<Response> {
        let (wal, patch_file) = self
            .cache
            .get_mut(summary.id())
            .ok_or(Error::CacheNotAvailable(*summary.id()))?;

        let patch = patch_file.append(events)?;
        let client_proof = wal.tree().head()?;

        let (response, server_proof) = self
            .client
            .patch_wal(summary.id(), &client_proof, &patch)
            .await?;

        let status = response.status();
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
                assert_proofs_eq(client_proof, server_proof)?;
                Ok(response)
            }
            StatusCode::CONFLICT => {
                let server_proof = server_proof.ok_or(Error::ServerProof)?;

                // Server replied with a proof that they have a
                // leaf node corresponding to our root hash which
                // indicates that we are behind the remote so we
                // can try to pull again and try to patch afterwards
                if let Some(_) = decode_match_proof(response.headers())? {
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
                    let response =
                        self.patch_wal(summary, patch.0.clone()).await?;

                    tracing::debug!(status = %response.status(),
                        "conflict on patch, retry patch status");

                    if response.status().is_success() {
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
                    Ok(response)
                } else {
                    Err(Error::Conflict(Conflict {
                        summary: summary.clone(),
                        local: client_proof.reduce(),
                        remote: server_proof.reduce(),
                    }))
                }
            }
            _ => Err(Error::ResponseCode(response.status().into())),
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
        let vault_path = self.vault_path(summary);

        if let Some(keeper) = self.current_mut() {
            if keeper.id() == summary.id() {
                // Rewrite the on-disc version if we are mirroring
                if mirror {
                    let buffer = encode(&vault)?;
                    let mut file = File::create(&vault_path)?;
                    file.write_all(&buffer)?;
                }

                // Update the in-memory version
                let keeper_vault = keeper.vault_mut();
                *keeper_vault = vault;
            }
        }
        Ok(())
    }
}
