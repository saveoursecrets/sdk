#![allow(clippy::result_large_err)]
#![allow(clippy::module_inception)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Networking support for the [sos-sdk crate](https://docs.rs/sos-sdk/latest/sos_sdk/).
//!
//! If the `listen` feature is enabled the client is compiled
//! with support for sending and listening for change notification over
//! a websocket connection.

mod account;
mod error;
#[cfg(feature = "pairing")]
pub mod pairing;

pub use sos_protocol as protocol;
pub use sos_sdk as sdk;

pub use account::*;
pub use error::Error;

#[cfg(feature = "hashcheck")]
pub use sos_protocol::hashcheck;

/// Remote result.
pub type RemoteResult = protocol::RemoteResult<Error>;

/// Sync result.
pub type SyncResult = protocol::SyncResult<Error>;

#[cfg(any(
    feature = "preferences",
    feature = "security-report",
    feature = "system-messages"
))]
pub use sos_account_extras as extras;

/// Result type for the client module.
pub type Result<T> = std::result::Result<T, error::Error>;

pub use sos_protocol::is_offline;
