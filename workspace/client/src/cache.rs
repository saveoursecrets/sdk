//! Cache of local WAL files.
use crate::{client::Client, Error, Result};
use reqwest::{Response, StatusCode};
use sos_core::{
    commit_tree::CommitProof,
    events::SyncEvent,
    file_identity::{FileIdentity, WAL_IDENTITY},
    gatekeeper::Gatekeeper,
    secret::SecretRef,
    vault::{CommitHash, Summary, Vault},
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
    /// Root directory to store cached files.
    cache_dir: PathBuf,
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
            cache_dir,
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

    /// Load a vault by attempting to fetch the WAL file and caching
    /// the result on disc.
    pub async fn load_vault(&mut self, summary: &Summary) -> Result<Vault> {
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
            let mut wal_file = WalFile::new(&cached_wal_path)?;
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
                        (mut wal_file, Some(proof)) => {
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
                            file.write(record_bytes)?;
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

                    // Build the vault from the WAL file
                    let (_, wal) = self.cache.get_mut(summary.id()).unwrap();
                    let vault = WalReducer::new().reduce(wal)?.build()?;

                    Ok(vault)
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
                        let vault = WalReducer::new().reduce(wal)?.build()?;
                        Ok(vault)
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

    /// Attempt to patch a remote WAL file.
    pub async fn patch_vault<'a>(
        &self,
        summary: &Summary,
        events: Vec<SyncEvent<'a>>,
    ) -> Result<Response> {
        if let Some((_, wal)) = self.cache.get(summary.id()) {
            let proof = wal.tree().head()?;

            let (response, _, server_proof) =
                self.client.patch_wal(summary.id(), &proof, events).await?;

            let status = response.status();
            match status {
                StatusCode::OK => {
                    println!("REMOTE SERVER PATCH WAS APPLIED");
                    Ok(response)
                }
                StatusCode::CONFLICT => {
                    todo!("handle patch conflict");
                }
                _ => {
                    todo!("handle patch errors");
                }
            }
        } else {
            todo!();
        }
    }

    /// Attempt to set the vault name on the remote server.
    pub async fn set_vault_name(
        &self,
        summary: &Summary,
        name: &str,
    ) -> Result<()> {
        let event = SyncEvent::SetVaultName(Cow::Borrowed(name));
        let response = self.patch_vault(summary, vec![event]).await?;
        if !response.status().is_success() {
            return Err(Error::SetVaultName(response.status().into()));
        }
        Ok(())
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
