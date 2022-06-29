//! Cache of local vaults and WAL files.
use crate::{client::Client, Error, Result};
use sos_core::{gatekeeper::Gatekeeper, vault::Summary};
use std::path::{Path, PathBuf};

/// Implements client-side caching of vaults and WAL files.
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

    /// Load the vault summaries from the remote server.
    pub async fn load_summaries(&mut self) -> Result<&[Summary]> {
        let summaries = self.client.list_vaults().await?;
        self.summaries = summaries;
        Ok(self.summaries())
    }
}
