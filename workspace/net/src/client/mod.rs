//! Traits and implementations for clients.

mod account;
#[cfg(feature = "hashcheck")]
pub mod hashcheck;
pub mod net;
mod sync;

mod error;

pub use account::*;
pub use error::Error;

pub use sync::{RemoteSync, SyncError};

/// Result type for the client module.
pub type Result<T> = std::result::Result<T, error::Error>;
