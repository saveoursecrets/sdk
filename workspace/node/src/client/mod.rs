//! Traits and implementations for clients.

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

use provider::{BoxedProvider, ProviderFactory};

#[cfg(not(target_arch = "wasm32"))]
use sos_core::account::AuthenticatedUser;

/// Authenticated user with storage provider.
#[cfg(not(target_arch = "wasm32"))]
pub struct UserStorage {
    /// Authenticated user.
    pub user: AuthenticatedUser,
    /// Storage provider.
    pub storage: BoxedProvider,
    /// Key pair for peer to peer connections.
    #[cfg(feature = "peer")]
    pub peer_key: libp2p::identity::Keypair,
    /// Factory user to create the storage provider.
    pub factory: ProviderFactory,
}
