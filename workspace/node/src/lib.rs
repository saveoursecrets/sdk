#![deny(missing_docs)]
//! Library for client and server communication.
use std::future::Future;
use tokio::runtime::Runtime;

pub mod client;
mod error;
mod sync;

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

/// Result type for the node library.
pub type Result<T> = std::result::Result<T, error::Error>;

pub use client::{ClientBuilder, PassphraseReader};
pub use error::Error;
pub use sync::*;
