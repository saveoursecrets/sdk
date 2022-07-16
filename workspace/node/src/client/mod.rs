//! Traits and implementations for clients.
use std::{fs::File, io::Read, path::PathBuf, sync::Arc};
use url::Url;

use std::future::Future;
use tokio::runtime::Runtime;

use async_trait::async_trait;
use net::RequestClient;
use web3_keystore::{decrypt, KeyStore};

use sos_core::{
    address::AddressStr,
    commit_tree::CommitTree,
    events::{ChangeNotification, SyncEvent, WalEvent},
    iter::WalFileRecord,
    secret::SecretRef,
    signer::SingleParty,
    vault::{Summary, Vault},
    wal::snapshot::{SnapShot, SnapShotManager},
    Gatekeeper,
};

use crate::sync::{SyncInfo, SyncStatus};

pub mod account;
mod changes_listener;
pub mod file_cache;
pub mod net;

mod error;
pub use changes_listener::ChangesListener;
pub use error::Error;

/// Result type for the client module.
pub type Result<T> = std::result::Result<T, error::Error>;

/// Runs a future blocking the current thread.
///
/// Exposed so we can merge the synchronous nature
/// of the shell REPL prompt with the asynchronous API
/// exposed by the HTTP client.
pub fn run_blocking<F, R>(func: F) -> Result<R>
where
    F: Future<Output = Result<R>> + Send,
    R: Send,
{
    Runtime::new().unwrap().block_on(func)
}

/// Trait for implementations that can read a passphrase.
pub trait PassphraseReader {
    /// Error generated attempting to read a passphrase.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Read a passphrase.
    fn read(&self) -> std::result::Result<String, Self::Error>;
}

/// Builds a client implementation.
pub struct ClientBuilder<E> {
    server: Url,
    keystore: PathBuf,
    keystore_passphrase: Option<String>,
    passphrase_reader: Option<Box<dyn PassphraseReader<Error = E>>>,
}

impl<E: std::error::Error + Send + Sync + 'static> ClientBuilder<E> {
    /// Create a new client builder.
    pub fn new(server: Url, keystore: PathBuf) -> Self {
        Self {
            server,
            keystore,
            keystore_passphrase: None,
            passphrase_reader: None,
        }
    }

    /// Set a specific passphrase for the keystore.
    pub fn with_keystore_passphrase(mut self, passphrase: String) -> Self {
        self.keystore_passphrase = Some(passphrase);
        self
    }

    /// Set a passphrase reader implementation.
    pub fn with_passphrase_reader(
        mut self,
        reader: Box<dyn PassphraseReader<Error = E>>,
    ) -> Self {
        self.passphrase_reader = Some(reader);
        self
    }

    /// Build a client implementation wrapping a signing key.
    pub fn build(self) -> Result<RequestClient> {
        if !self.keystore.exists() {
            return Err(Error::NotFile(self.keystore));
        }

        // Decrypt the keystore and create the client.
        let mut keystore_file = File::open(&self.keystore)?;
        let mut keystore_bytes = Vec::new();
        keystore_file.read_to_end(&mut keystore_bytes)?;
        let keystore: KeyStore = serde_json::from_slice(&keystore_bytes)?;

        let passphrase = if let Some(passphrase) = self.keystore_passphrase {
            passphrase
        } else if let Some(reader) = self.passphrase_reader {
            reader.read().map_err(Box::from)?
        } else {
            panic!("client builder requires either a passphrase or passphrase reader");
        };
        let signing_bytes = decrypt(&keystore, &passphrase)?;

        let signing_key: [u8; 32] = signing_bytes.as_slice().try_into()?;
        let signer: SingleParty = (&signing_key).try_into()?;
        Ok(RequestClient::new(self.server, Arc::new(signer)))
    }
}

/// Trait for types that cache vaults locally; supports a *current* view
/// into a selected vault and allows making changes to the currently
/// selected vault.
#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait LocalCache {
    /// Get the address of the current user.
    fn address(&self) -> Result<AddressStr>;

    /// Get the underlying client.
    fn client(&self) -> &RequestClient;

    /// Get the vault summaries for this cache.
    fn vaults(&self) -> &[Summary];

    /// Get the snapshot manager for this cache.
    fn snapshots(&self) -> &SnapShotManager;

    /// Take a snapshot of the WAL for the given vault.
    fn take_snapshot(&self, summary: &Summary) -> Result<(SnapShot, bool)>;

    /// Get the history for a WAL file.
    fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(WalFileRecord, WalEvent<'_>)>>;

    /// Verify a WAL log.
    fn verify(&self, summary: &Summary) -> Result<()>;

    /// Compact a WAL file.
    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)>;

    /// Respond to a change notification.
    async fn handle_change(
        &mut self,
        change: ChangeNotification,
    ) -> Result<()>;

    /// Load the vault summaries from the remote server.
    async fn load_vaults(&mut self) -> Result<&[Summary]>;

    /// Attempt to find a summary in this cache.
    fn find_vault(&self, vault: &SecretRef) -> Option<&Summary>;

    /// Create a new account and default login vault.
    async fn create_account(
        &mut self,
        name: Option<String>,
    ) -> Result<(String, Summary)>;

    /// Create a new vault.
    async fn create_vault(
        &mut self,
        name: String,
    ) -> Result<(String, Summary)>;

    /// Remove a vault.
    async fn remove_vault(&mut self, summary: &Summary) -> Result<()>;

    /// Attempt to set the vault name on the remote server.
    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<()>;

    /// Get a comparison between a local WAL and remote WAL.
    ///
    /// If a patch file has unsaved events then the number
    /// of pending events is returned along with the `SyncStatus`.
    async fn vault_status(
        &self,
        summary: &Summary,
    ) -> Result<(SyncStatus, Option<usize>)>;

    /// Update an existing vault.
    async fn update_vault(
        &mut self,
        summary: &Summary,
        vault: &Vault,
        events: Vec<WalEvent<'static>>,
    ) -> Result<()>;

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

    /// Download changes from the remote server.
    async fn pull(
        &mut self,
        summary: &Summary,
        force: bool,
    ) -> Result<SyncInfo>;

    /// Upload changes to the remote server.
    async fn push(
        &mut self,
        summary: &Summary,
        force: bool,
    ) -> Result<SyncInfo>;
}
