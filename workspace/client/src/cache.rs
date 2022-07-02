//! Cache of local WAL files.
use crate::{
    client::{decode_leaf_proof, Client},
    Error, Result,
};
use async_recursion::async_recursion;
use reqwest::{Response, StatusCode};
use sos_core::{
    commit_tree::{decode_proof, CommitProof, Comparison},
    events::{Patch, SyncEvent, WalEvent},
    file_identity::{FileIdentity, WAL_IDENTITY},
    gatekeeper::Gatekeeper,
    secret::SecretRef,
    vault::{CommitHash, Header, Summary, Vault},
    wal::{file::WalFile, reducer::WalReducer, WalProvider},
};
use std::{
    borrow::Cow,
    collections::HashMap,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
};
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
    cache: HashMap<Uuid, (PathBuf, WalFile)>,
}

impl Cache {
    /// Create a new cache using the given client and root directory.
    pub fn new<D: AsRef<Path>>(client: Client, cache_dir: D) -> Result<Self> {
        let cache_dir = cache_dir.as_ref().to_path_buf();
        if !cache_dir.is_dir() {
            return Err(Error::NotDirectory(cache_dir));
        }

        let address = client.address()?;
        let address = format!("{}", address);
        let user_dir = cache_dir.join(&address);
        std::fs::create_dir_all(&user_dir)?;

        Ok(Self {
            summaries: Default::default(),
            current: None,
            client,
            user_dir,
            cache: Default::default(),
        })
    }

    /// Get the vault summaries for this cache.
    pub fn summaries(&self) -> &[Summary] {
        self.summaries.as_slice()
    }

    /// Get the client for server communication.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Get the current in-memory vault access.
    pub fn current(&self) -> Option<&Gatekeeper> {
        self.current.as_ref()
    }

    /// Get a mutable reference to the current in-memory vault access.
    pub fn current_mut(&mut self) -> Option<&mut Gatekeeper> {
        self.current.as_mut()
    }

    /// Set the currently active in-memory vault.
    pub fn set_current(&mut self, current: Option<Gatekeeper>) {
        self.current = current;
    }

    /// Attempt to find a summary in this cache.
    pub fn find_summary(&self, vault: &SecretRef) -> Option<&Summary> {
        match vault {
            SecretRef::Name(name) => {
                self.summaries.iter().find(|s| s.name() == name)
            }
            SecretRef::Id(id) => self.summaries.iter().find(|s| s.id() == id),
        }
    }

    /// Load the vault summaries from the remote server.
    pub async fn load_summaries(&mut self) -> Result<&[Summary]> {
        let summaries = self.client.list_vaults().await?;
        self.load_caches(&summaries)?;
        self.summaries = summaries;
        Ok(self.summaries())
    }

    fn load_caches(&mut self, summaries: &[Summary]) -> Result<()> {
        for summary in summaries {
            let cached_wal_path = self.wal_path(summary);
            if cached_wal_path.exists() {
                let mut wal_file = WalFile::new(&cached_wal_path)?;
                wal_file.load_tree()?;
                self.cache
                    .insert(*summary.id(), (cached_wal_path, wal_file));
            }
        }
        Ok(())
    }

    fn wal_path(&self, summary: &Summary) -> PathBuf {
        let wal_name = format!("{}.{}", summary.id(), WalFile::extension());
        self.user_dir.join(&wal_name)
    }

    pub fn wal_file(&self, summary: &Summary) -> Option<&(PathBuf, WalFile)> {
        self.cache.get(summary.id())
    }

    /// Fetch the remote WAL file.
    pub async fn pull_wal<'a>(
        &'a mut self,
        summary: &Summary,
    ) -> Result<&'a mut WalFile> {
        let cached_wal_path = self.wal_path(summary);

        // Cache already exists so attempt to get a diff of records
        // to append
        let cached = if cached_wal_path.exists() {
            let mut wal_file = WalFile::new(&cached_wal_path)?;
            wal_file.load_tree()?;
            let proof = wal_file.tree().head()?;
            (wal_file, Some(proof))
        // Otherwise prepare a new WAL cache
        } else {
            let wal_file = WalFile::new(&cached_wal_path)?;
            (wal_file, None)
        };

        let (response, server_proof) =
            self.client.get_wal(summary.id(), cached.1.as_ref()).await?;

        let status = response.status();

        match status {
            StatusCode::OK => {
                if let Some(server_proof) = server_proof {
                    let (client_proof, wal_file) = match cached {
                        // If we sent a proof to the server then we
                        // are expecting a diff of records
                        (mut wal_file, Some(_proof)) => {
                            let buffer = response.bytes().await?;

                            // Check the identity looks good
                            FileIdentity::read_slice(&buffer, &WAL_IDENTITY)?;

                            // Get buffer of log records after the identity
                            let record_bytes =
                                &buffer[WAL_IDENTITY.len() - 1..buffer.len()];

                            // Append the diff bytes without the identity
                            let mut file = OpenOptions::new()
                                .write(true)
                                .append(true)
                                .open(&cached_wal_path)?;
                            file.write_all(record_bytes)?;
                            wal_file.load_tree()?;

                            (wal_file.tree().head()?, wal_file)
                        }
                        // Otherwise the server should send us the entire
                        // WAL file
                        (mut wal_file, None) => {
                            // Read in the entire response buffer
                            let buffer = response.bytes().await?;

                            // Check the identity looks good
                            FileIdentity::read_slice(&buffer, &WAL_IDENTITY)?;

                            std::fs::write(&cached_wal_path, &buffer)?;
                            wal_file.load_tree()?;

                            (wal_file.tree().head()?, wal_file)
                        }
                    };

                    assert_proofs_eq(client_proof, server_proof)?;

                    self.cache
                        .insert(*summary.id(), (cached_wal_path, wal_file));

                    let (_, wal) = self.cache.get_mut(summary.id()).unwrap();

                    Ok(wal)

                    /*
                    // Build the vault from the WAL file
                    //let (_, wal) = self.cache.get_mut(summary.id()).unwrap();
                    let vault = WalReducer::new().reduce(wal)?.build()?;

                    Ok(vault)
                    */
                } else {
                    Err(Error::ServerProof)
                }
            }
            StatusCode::NOT_MODIFIED => {
                // Build the vault from the cached WAL file
                if let Some((_, wal)) = self.cache.get_mut(summary.id()) {
                    if let Some(server_proof) = server_proof {
                        let client_proof = wal.tree().head()?;
                        assert_proofs_eq(client_proof, server_proof)?;

                        /*
                        let vault = WalReducer::new().reduce(wal)?.build()?;
                        Ok(vault)
                        */

                        Ok(wal)
                    } else {
                        Err(Error::ServerProof)
                    }
                } else {
                    Err(Error::CacheNotAvailable(*summary.id()))
                }
            }
            StatusCode::CONFLICT => {
                todo!("handle conflicts");
            }
            _ => {
                todo!("handle errors {:#?}", response);
            }
        }
    }

    /// Load a vault by attempting to fetch the WAL file and caching
    /// the result on disc then building a vault from the WAL.
    pub async fn load_vault(&mut self, summary: &Summary) -> Result<Vault> {
        let wal = self.pull_wal(summary).await?;
        let vault = WalReducer::new().reduce(wal)?.build()?;
        Ok(vault)
    }

    /// Attempt to patch a remote WAL file.
    #[async_recursion]
    pub async fn patch_vault(
        &mut self,
        summary: &Summary,
        events: Vec<SyncEvent<'async_recursion>>,
    ) -> Result<Response> {
        if let Some((_, wal)) = self.cache.get_mut(summary.id()) {
            let patch = Patch(events);
            let proof = wal.tree().head()?;
            let (response, server_proof) =
                self.client.patch_wal(summary.id(), &proof, &patch).await?;

            let status = response.status();
            match status {
                StatusCode::OK => {
                    let server_proof =
                        server_proof.ok_or(Error::ServerProof)?;
                    let change_set = patch.0;

                    // Apply changes to the local WAL file
                    let mut changes = Vec::new();
                    for event in change_set {
                        if let Ok::<WalEvent<'_>, sos_core::Error>(
                            wal_event,
                        ) = event.try_into()
                        {
                            changes.push(wal_event);
                        }
                    }

                    // Pass the expected root hash so changes are reverted
                    // if the root hashes do not match
                    wal.apply(changes, Some(CommitHash(server_proof.0)))?;

                    let client_proof = wal.tree().head()?;
                    assert_proofs_eq(client_proof, server_proof)?;
                    Ok(response)
                }
                StatusCode::CONFLICT => {
                    let server_proof =
                        server_proof.ok_or(Error::ServerProof)?;

                    println!(
                        "Got conflict response {:#?}",
                        response.headers()
                    );

                    // Server replied with a proof that they have a
                    // leaf node corresponding to our root hash
                    if let Some(leaf_proof) =
                        decode_leaf_proof(response.headers())?
                    {
                        let proof = decode_proof(&leaf_proof)?;
                        let other_root = server_proof.0;
                        let commit_proof = CommitProof(other_root, proof);
                        let comparison = wal.tree().compare(commit_proof)?;

                        println!("got leaf comparison {:#?}", comparison);

                        match comparison {
                            Comparison::Equal => {
                                // We got a conflict from the server so this
                                // should not happen but if it does then it's ok
                                Ok(response)
                            }
                            Comparison::Contains(index, _) => {
                                // The leaf proof from the server matches
                                // the index for our last leaf so we can
                                // go ahead and pull a diff from the server
                                if index == wal.tree().len() - 1 {
                                    println!("pull wal diff from the server");

                                    // Pull the updated WAL from the server
                                    let _ = self.pull_wal(summary).await?;

                                    println!("retry patching changes");

                                    // Retry sending our local changes to
                                    // the remote WAL
                                    let response = self
                                        .patch_vault(summary, patch.0.clone())
                                        .await?;

                                    if response.status().is_success() {
                                        println!("remote patch was applied");

                                        println!("Apply the changes to our locwal WAL");
                                        let updated_vault =
                                            self.load_vault(summary).await?;

                                        if let Some(keeper) =
                                            self.current_mut()
                                        {
                                            if keeper.id() == summary.id() {
                                                let existing_vault =
                                                    keeper.vault_mut();
                                                *existing_vault =
                                                    updated_vault;
                                                println!("Merge updated vault data with our local changes!!!!");
                                            }
                                        }
                                    }

                                    Ok(response)
                                } else {
                                    self.conflict_pull_sync()?;
                                    Ok(response)
                                }
                            }
                            Comparison::Unknown => {
                                self.conflict_pull_sync()?;
                                Ok(response)
                            }
                        }
                    } else {
                        self.conflict_pull_sync()?;
                        Ok(response)
                    }
                }
                _ => {
                    todo!("handle patch errors");
                }
            }
        } else {
            Err(Error::CacheNotAvailable(*summary.id()))
        }
    }

    fn conflict_pull_sync(&mut self) -> Result<()> {
        todo!("handle patch conflict that requires complete sync");
    }

    /// Attempt to set the vault name on the remote server.
    pub async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<Response> {
        let event = SyncEvent::SetVaultName(Cow::Borrowed(name));
        let response = self.patch_vault(summary, vec![event]).await?;

        if response.status().is_success() {
            for item in self.summaries.iter_mut() {
                if item.id() == summary.id() {
                    item.set_name(name.to_string());
                }
            }
        }

        Ok(response)
    }

    /// Create a new WAL file.
    pub async fn create_wal(&mut self, vault: Vec<u8>) -> Result<Response> {
        let summary = Header::read_summary_slice(&vault)?;
        let (response, _) = self.client.create_wal(vault).await?;
        if response.status().is_success() {
            self.summaries.push(summary);
        }
        Ok(response)
    }

    /// Delete an existing WAL file.
    pub async fn delete_wal(
        &mut self,
        summary: &Summary,
    ) -> Result<Response> {
        let current_id = self.current().map(|c| c.id().clone());

        let (response, _) = self.client.delete_wal(summary.id()).await?;

        if response.status().is_success() {
            // If the deleted vault is the currently selected
            // vault we must clear the selection
            if let Some(id) = &current_id {
                if id == summary.id() {
                    self.set_current(None);
                }
            }

            let index =
                self.summaries.iter().position(|s| s.id() == summary.id());
            if let Some(index) = index {
                self.summaries.remove(index);
            }
        }

        Ok(response)
    }

    /// Get a comparison between a local WAL and remote WAL.
    pub async fn head_wal(
        &self,
        summary: &Summary,
    ) -> Result<(CommitProof, CommitProof)> {
        if let Some((_, wal)) = self.cache.get(summary.id()) {
            let client_proof = wal.tree().head()?;
            let (_response, server_proof) =
                self.client.head_wal(summary.id()).await?;
            Ok((client_proof, server_proof))
        } else {
            Err(Error::CacheNotAvailable(*summary.id()))
        }
    }

    /// Get the default root directory used for caching client data.
    pub fn cache_dir() -> Result<PathBuf> {
        let data_local_dir =
            dirs::data_local_dir().ok_or(Error::NoDataLocalDir)?;
        let cache_dir = data_local_dir.join("sos");
        if !cache_dir.exists() {
            std::fs::create_dir(&cache_dir)?;
        }
        Ok(cache_dir)
    }
}
