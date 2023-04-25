#![allow(clippy::result_large_err)]
#![allow(clippy::module_inception)]
#![deny(missing_docs)]
//! Library for network communication.

#[cfg(not(target_arch = "wasm32"))]
mod file_locks;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "device")]
pub mod device;
#[cfg(feature = "peer")]
pub mod peer;
#[cfg(feature = "server")]
pub mod server;

mod error;

/// Result type for the node module.
pub type Result<T> = std::result::Result<T, error::Error>;
pub use error::Error;

#[cfg(not(target_arch = "wasm32"))]
pub use file_locks::FileLocks;

use sos_core::account::AuthenticatedUser;
use client::provider::BoxedProvider;

/// Authenticated user with storage provider.
pub struct UserStorage {
    /// Authenticated user.
    pub user: AuthenticatedUser,
    /// Storage provider.
    pub storage: BoxedProvider,
    /// Key pair for peer to peer connections.
    #[cfg(feature = "peer")]
    pub peer_key: libp2p::identity::Keypair,
}
