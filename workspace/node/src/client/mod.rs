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
