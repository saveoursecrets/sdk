#![deny(missing_docs)]
//! Library for network communication.

extern crate sha3;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "device")]
pub mod device;
#[cfg(feature = "peer")]
pub mod peer;
#[cfg(feature = "server")]
pub mod server;

mod error;
pub mod session;
pub mod sync;

/// Result type for the node module.
pub type Result<T> = std::result::Result<T, error::Error>;
pub use error::Error;
