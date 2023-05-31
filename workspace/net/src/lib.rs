#![allow(clippy::result_large_err)]
#![allow(clippy::module_inception)]
#![deny(missing_docs)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Networking library for the SOS SDK.

#[cfg(not(target_arch = "wasm32"))]
mod file_locks;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "device")]
pub mod device;
#[cfg(all(feature = "peer", not(target_arch = "wasm32")))]
pub mod peer;
#[cfg(feature = "server")]
pub mod server;

mod error;

/// Result type for the network module.
pub type Result<T> = std::result::Result<T, error::Error>;
pub use error::Error;

#[cfg(not(target_arch = "wasm32"))]
pub use file_locks::FileLocks;

#[cfg(feature = "migrate")]
pub use sos_migrate as migrate;
