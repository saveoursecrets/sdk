//! Client user account and types for bridging with remote origins.

mod account;
#[cfg(feature = "device")]
pub mod enrollment;
mod error;
#[cfg(feature = "hashcheck")]
pub mod hashcheck;
mod net;
mod sync;

pub use account::*;
pub use error::Error;
pub use net::HttpClient;
#[cfg(feature = "listen")]
pub use net::{changes, connect, ListenOptions, WebSocketHandle};
pub use sync::{RemoteSync, SyncError, SyncOptions};

/// Result type for the client module.
pub type Result<T> = std::result::Result<T, error::Error>;
