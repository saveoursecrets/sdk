//! Traits and implementations for clients.
use std::{fs::File, io::Read, path::PathBuf};
use url::Url;

use std::future::Future;

use async_trait::async_trait;
use net::RequestClient;
use web3_keystore::{decrypt, KeyStore};

use secrecy::{ExposeSecret, SecretString};
use sos_core::{
    address::AddressStr,
    commit_tree::CommitTree,
    events::{ChangeNotification, SyncEvent, WalEvent},
    secret::SecretRef,
    signer::{Signer, SingleParty},
    vault::{Summary, Vault},
    wal::{
        snapshot::{SnapShot, SnapShotManager},
        WalProvider,
    },
    Gatekeeper, PatchProvider,
};

use crate::sync::{SyncInfo, SyncStatus};

#[cfg(not(target_arch = "wasm32"))]
pub mod account;

#[cfg(not(target_arch = "wasm32"))]
mod changes_listener;
pub mod net;
pub mod node_cache;
pub mod spot;

mod error;

#[cfg(not(target_arch = "wasm32"))]
pub use changes_listener::ChangesListener;
pub use error::Error;

/// Result type for the client module.
pub type Result<T> = std::result::Result<T, error::Error>;

/// Runs a future blocking the current thread.
///
/// Exposed so we can merge the synchronous nature
/// of the shell REPL prompt with the asynchronous API
/// exposed by the HTTP client.
#[cfg(not(target_arch = "wasm32"))]
pub fn run_blocking<F, R>(func: F) -> Result<R>
where
    F: Future<Output = Result<R>> + Send,
    R: Send,
{
    use tokio::runtime::Runtime;
    Runtime::new().unwrap().block_on(func)
}

/// Runs a future blocking the current thread.
#[cfg(target_arch = "wasm32")]
pub fn run_blocking<F, R>(func: F) -> Result<R>
where
    F: Future<Output = Result<R>>,
{
    use tokio::runtime::Builder;
    Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(func)
}

/// Trait for implementations that can read a passphrase.
pub trait PassphraseReader {
    /// Error generated attempting to read a passphrase.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Read a passphrase.
    fn read(&self) -> std::result::Result<SecretString, Self::Error>;
}

#[cfg(feature = "agent-client")]
async fn get_agent_key(address: &AddressStr) -> Result<Option<[u8; 32]>> {
    use crate::agent::client::KeyAgentClient;
    Ok(KeyAgentClient::get(address.clone().into()).await)
}

#[cfg(feature = "agent-client")]
async fn set_agent_key(
    address: AddressStr,
    value: [u8; 32],
) -> Result<Option<()>> {
    use crate::agent::client::KeyAgentClient;
    Ok(KeyAgentClient::set(address.into(), value).await)
}

#[cfg(not(feature = "agent-client"))]
async fn get_agent_key(_address: &AddressStr) -> Result<Option<[u8; 32]>> {
    Ok(None)
}

#[cfg(not(feature = "agent-client"))]
async fn set_agent_key(
    _address: AddressStr,
    _value: [u8; 32],
) -> Result<Option<()>> {
    Ok(None)
}

/// Builds a client implementation.
pub struct ClientBuilder<E> {
    server: Url,
    keystore: PathBuf,
    keystore_passphrase: Option<SecretString>,
    passphrase_reader: Option<Box<dyn PassphraseReader<Error = E>>>,
    use_agent: bool,
}

impl<E> ClientBuilder<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Create a new client builder.
    pub fn new(server: Url, keystore: PathBuf) -> Self {
        Self {
            server,
            keystore,
            keystore_passphrase: None,
            passphrase_reader: None,
            use_agent: false,
        }
    }

    /// Set a specific passphrase for the keystore.
    pub fn with_keystore_passphrase(
        mut self,
        passphrase: SecretString,
    ) -> Self {
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

    /// Set whether to use the key agent integration.
    pub fn with_use_agent(mut self, use_agent: bool) -> Self {
        self.use_agent = use_agent;
        self
    }

    /// Build a client implementation wrapping a signing key.
    pub fn build(self) -> Result<RequestClient<SingleParty>> {
        if !self.keystore.exists() {
            return Err(Error::NotFile(self.keystore));
        }

        // Decrypt the keystore and create the client.
        let mut keystore_file = File::open(&self.keystore)?;
        let mut keystore_bytes = Vec::new();
        keystore_file.read_to_end(&mut keystore_bytes)?;
        let keystore: KeyStore = serde_json::from_slice(&keystore_bytes)?;

        let address = if let Some(address) = &keystore.address {
            let address: AddressStr = address.parse()?;
            Some(address)
        } else {
            None
        };

        let agent_key = if self.use_agent {
            if let Some(address) = &address {
                run_blocking(get_agent_key(address))?
            } else {
                None
            }
        } else {
            None
        };

        let signing_key: [u8; 32] = if let Some(signing_key) = agent_key {
            signing_key
        } else {
            let passphrase = if let Some(passphrase) =
                self.keystore_passphrase
            {
                passphrase
            } else if let Some(reader) = self.passphrase_reader {
                reader.read().map_err(Box::from)?
            } else {
                panic!("client builder requires either a passphrase or passphrase reader");
            };

            let signing_bytes =
                decrypt(&keystore, passphrase.expose_secret())?;
            let signing_key: [u8; 32] =
                signing_bytes.as_slice().try_into()?;

            if self.use_agent {
                if let Some(address) = address {
                    run_blocking(set_agent_key(
                        address.into(),
                        signing_key.clone(),
                    ))?;
                }
            }

            signing_key
        };
        let signer: SingleParty = (&signing_key).try_into()?;
        Ok(RequestClient::new(self.server, signer))
    }
}

/// Trait for types that cache vaults locally; supports a *current* view
/// into a selected vault and allows making changes to the currently
/// selected vault.
#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait LocalCache<S, W, P>
where
    S: Signer + Send + Sync + 'static,
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    /// Get the address of the current user.
    fn address(&self) -> Result<AddressStr>;

    /// Get the underlying client.
    fn client(&self) -> &RequestClient<S>;

    /// Get the vault summaries for this cache.
    fn vaults(&self) -> &[Summary];

    /// Get the snapshot manager for this cache.
    fn snapshots(&self) -> Option<&SnapShotManager>;

    /// Take a snapshot of the WAL for the given vault.
    ///
    /// Snapshots must be enabled.
    fn take_snapshot(&self, summary: &Summary) -> Result<(SnapShot, bool)>;

    /// Get the history for a WAL provider.
    fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(W::Item, WalEvent<'_>)>>;

    /// Verify a WAL log.
    fn verify(&self, summary: &Summary) -> Result<()>;

    /// Compact a WAL provider.
    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)>;

    /// Respond to a change notification.
    async fn handle_change(
        &mut self,
        change: ChangeNotification,
    ) -> Result<()>;

    /// Load the vault summaries from a remote node.
    async fn load_vaults(&mut self) -> Result<&[Summary]>;

    /// Attempt to find a summary in this cache.
    fn find_vault(&self, vault: &SecretRef) -> Option<&Summary>;

    /// Create a new account and default login vault.
    async fn create_account(
        &mut self,
        name: Option<String>,
    ) -> Result<(SecretString, Summary)>;

    /// Create a new vault.
    async fn create_vault(
        &mut self,
        name: String,
    ) -> Result<(SecretString, Summary)>;

    /// Remove a vault.
    async fn remove_vault(&mut self, summary: &Summary) -> Result<()>;

    /// Attempt to set the vault name on the remote node.
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
