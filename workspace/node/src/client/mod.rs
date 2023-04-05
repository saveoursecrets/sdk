//! Traits and implementations for clients.

#[cfg(not(target_arch = "wasm32"))]
use std::future::Future;

use secrecy::SecretString;

#[cfg(not(target_arch = "wasm32"))]
pub mod account;

#[cfg(not(target_arch = "wasm32"))]
pub mod account_manager;

#[cfg(not(target_arch = "wasm32"))]
mod changes_listener;
pub mod net;
pub mod provider;

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
    F: Future<Output = Result<R>>,
{
    use tokio::runtime::Runtime;
    Runtime::new().unwrap().block_on(func)
}

/// Trait for implementations that can read a passphrase.
pub trait PassphraseReader {
    /// Error generated attempting to read a passphrase.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Read a passphrase.
    fn read(&self) -> std::result::Result<SecretString, Self::Error>;
}

/*
/// Builds a client implementation.
pub struct SignerBuilder<E> {
    passphrase_reader: Option<Box<dyn PassphraseReader<Error = E>>>,
    signer: BoxedSigner,
    use_agent: bool,
}

impl<E> SignerBuilder<E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    /// Create a new client builder.
    pub fn new(signer: BoxedSigner) -> Self {
        Self {
            passphrase_reader: None,
            signer,
            use_agent: false,
        }
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
        let agent_key = if self.use_agent {
            if let Some(address) = &address {
                agent_helpers::blocking_get_agent_key(address)?
            } else {
                None
            }
        } else {
            None
        };

        let signing_key: [u8; 32] = if let Some(signing_key) = agent_key {
            signing_key
        } else if let Some(signer) = self.signer {
            let signing_bytes = signer.to_bytes();
            let signing_key: [u8; 32] =
                signing_bytes.as_slice().try_into()?;

            if self.use_agent {
                if let Some(address) = address {
                    agent_helpers::blocking_set_agent_key(
                        address.into(),
                        signing_key.clone(),
                    )?;
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
*/

#[cfg(all(not(target_arch = "wasm32"), feature = "agent-client"))]
mod agent_helpers {
    use super::{run_blocking, Result};
    use web3_address::ethereum::Address;

    async fn get_agent_key(address: &Address) -> Result<Option<[u8; 32]>> {
        use crate::agent::client::KeyAgentClient;
        Ok(KeyAgentClient::get(address.clone().into()).await)
    }

    async fn set_agent_key(
        address: Address,
        value: [u8; 32],
    ) -> Result<Option<()>> {
        use crate::agent::client::KeyAgentClient;
        Ok(KeyAgentClient::set(address.into(), value).await)
    }

    pub(crate) fn blocking_get_agent_key(
        address: &Address,
    ) -> Result<Option<[u8; 32]>> {
        run_blocking(get_agent_key(address))
    }

    pub(crate) fn blocking_set_agent_key(
        address: Address,
        value: [u8; 32],
    ) -> Result<Option<()>> {
        run_blocking(set_agent_key(address.into(), value))
    }
}

#[cfg(any(target_arch = "wasm32", not(feature = "agent-client")))]
mod agent_helpers {
    use super::Result;
    use web3_address::ethereum::Address;

    pub(crate) fn blocking_get_agent_key(
        _address: &Address,
    ) -> Result<Option<[u8; 32]>> {
        Ok(None)
    }

    pub(crate) fn blocking_set_agent_key(
        _address: Address,
        _value: [u8; 32],
    ) -> Result<Option<()>> {
        Ok(None)
    }
}
