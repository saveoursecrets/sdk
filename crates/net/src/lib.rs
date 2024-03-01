#![allow(clippy::result_large_err)]
#![allow(clippy::module_inception)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Networking library for the [sos-sdk crate](https://docs.rs/sos-sdk/latest/sos_sdk/).
//!
//! If the `listen` feature is enabled the server and client are compiled
//! with support for sending and listening for change notification over
//! a websocket connection.

#[cfg(feature = "client")]
pub mod client;
mod error;
#[cfg(feature = "pairing")]
pub mod relay;
#[cfg(feature = "server")]
pub mod server;

/// Result type for the network module.
pub type Result<T> = std::result::Result<T, error::Error>;
pub use error::Error;

#[cfg(feature = "client")]
pub use reqwest;

pub use sos_sdk as sdk;

#[cfg(feature = "listen")]
use sos_sdk::signer::ecdsa::Address;

/// Notification sent by the server when changes were made.
#[cfg(feature = "listen")]
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct ChangeNotification {
    /// Account owner address.
    address: Address,
}

#[cfg(feature = "listen")]
impl ChangeNotification {
    /// Create a new change notification.
    pub fn new(address: &Address) -> Self {
        Self { address: *address }
    }

    /// Address of the account owner.
    pub fn address(&self) -> &Address {
        &self.address
    }
}