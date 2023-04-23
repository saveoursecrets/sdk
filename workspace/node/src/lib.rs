#![deny(missing_docs)]
//! Library for network communication.

extern crate sha3;

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
pub mod session;

/// Result type for the node module.
pub type Result<T> = std::result::Result<T, error::Error>;
pub use error::Error;

#[cfg(not(target_arch = "wasm32"))]
pub use file_locks::FileLocks;
