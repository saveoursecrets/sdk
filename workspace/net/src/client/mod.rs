//! Traits and implementations for clients.

mod account;
#[cfg(not(target_arch = "wasm32"))]
mod changes_listener;
#[cfg(feature = "hashcheck")]
pub mod hashcheck;
pub mod net;
mod sync;

mod error;

pub use account::*;
#[cfg(not(target_arch = "wasm32"))]
pub use changes_listener::ChangesListener;
pub use error::Error;

pub use sync::{RemoteSync, SyncError};

/// Result type for the client module.
pub type Result<T> = std::result::Result<T, error::Error>;
