//! Traits and implementations for clients.
use std::{fs::File, io::Read, path::PathBuf};

use std::future::Future;



use web3_keystore::{decrypt, KeyStore};

use secrecy::{ExposeSecret, SecretString};
use sos_core::{
    address::AddressStr,
    signer::{BoxedSigner, Signer, SingleParty},
    wal::{
        WalProvider,
    }, PatchProvider,
};



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
pub struct SignerBuilder<E> {
    keystore: PathBuf,
    keystore_passphrase: Option<SecretString>,
    passphrase_reader: Option<Box<dyn PassphraseReader<Error = E>>>,
    use_agent: bool,
}

impl<E> SignerBuilder<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Create a new client builder.
    pub fn new(keystore: PathBuf) -> Self {
        Self {
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
    pub fn build(self) -> Result<BoxedSigner> {
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
        let signer: Box<dyn Signer + Send + Sync + 'static> =
            Box::new(signer);
        Ok(signer)
    }
}
