//! Peer to peer networking.

mod behaviour;
pub mod error;
pub mod network;
mod protocol;
mod transport;

// Re-exports
pub use error::Error;
pub use libp2p;

/// Result type for the peer module.
pub type Result<T> = std::result::Result<T, error::Error>;
