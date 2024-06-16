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
pub(crate) mod commits;
mod error;
pub mod protocol;
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
use sos_sdk::{
    commit::CommitHash, signer::ecdsa::Address, sync::MergeOutcome,
};

// Expose for test specs.
#[cfg(debug_assertions)]
pub use commits::*;

/// Notification sent by the server when changes were made.
#[cfg(feature = "listen")]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct ChangeNotification {
    /// Account owner address.
    address: Address,
    /// Connection identifier that made the change.
    connection_id: String,
    /// Root commit for the entire account.
    root: CommitHash,
    /// Merge outcome.
    outcome: MergeOutcome,
}

#[cfg(feature = "listen")]
impl ChangeNotification {
    /// Create a new change notification.
    pub fn new(
        address: &Address,
        connection_id: String,
        root: CommitHash,
        outcome: MergeOutcome,
    ) -> Self {
        Self {
            address: *address,
            connection_id,
            root,
            outcome,
        }
    }

    /// Address of the account owner.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Connection identifier.
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    /// Merge outcome.
    pub fn outcome(&self) -> &MergeOutcome {
        &self.outcome
    }
}
