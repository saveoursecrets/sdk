use std::future::Future;
use tokio::runtime::Runtime;

pub mod client;
mod error;

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

pub use error::Error;
pub type Result<T> = std::result::Result<T, error::Error>;

pub use client::account::{
    create_account, create_signing_key, login, ClientCredentials, ClientKey,
};
pub use client::cache::{
    ClientCache, FileCache, SyncInfo, SyncKind, SyncStatus,
};
pub use client::http_client::Client;
pub use client::{ClientBuilder, PassphraseReader};
