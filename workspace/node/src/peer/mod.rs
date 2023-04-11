//! Peer to peer networking.

mod behaviour;
pub mod error;
pub mod events;
pub mod network;
pub mod protocol;
pub mod rendezvous;
mod transport;

// Re-exports
pub use error::Error;
pub use libp2p;

/// Result type for the peer module.
pub type Result<T> = std::result::Result<T, error::Error>;
