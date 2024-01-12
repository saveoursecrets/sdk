#![allow(clippy::result_large_err)]
#![allow(clippy::module_inception)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Networking library for the [sos-sdk crate](https://docs.rs/sos-sdk/latest/sos_sdk/).
//!
//! Provides a client and server that communicate over
//! encrypted channels using the [noise protocol](https://noiseprotocol.org/).
//!
//! If the `listen` feature is enabled the server and client are compiled
//! with support for sending and listening for change notification over
//! a websocket connection.

#[cfg(not(target_arch = "wasm32"))]
mod file_locks;

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "device")]
pub mod device;
#[cfg(feature = "server")]
pub mod server;

#[cfg(any(feature = "client", feature = "server"))]
pub mod events;

#[cfg(any(feature = "client", feature = "server"))]
pub mod rpc;

#[cfg(any(feature = "client", feature = "server"))]
mod encoding;

mod error;

/// Result type for the network module.
pub type Result<T> = std::result::Result<T, error::Error>;
pub use error::Error;

#[cfg(not(target_arch = "wasm32"))]
pub use file_locks::FileLocks;

#[cfg(feature = "client")]
pub use reqwest;

pub use sos_sdk as sdk;
