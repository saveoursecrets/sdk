//! Networking support for the [Save Our Secrets](https://saveoursecrets.com) SDK.
//!
//! If the `listen` feature is enabled the client is compiled
//! with support for sending and listening for change notification over
//! a websocket connection.
#![allow(clippy::result_large_err)]
#![allow(clippy::module_inception)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::large_enum_variant)]

mod account;
mod error;
#[cfg(feature = "pairing")]
pub mod pairing;

pub use account::*;
pub use error::Error;

#[cfg(feature = "hashcheck")]
pub use sos_protocol::hashcheck;

/// Remote result.
pub type RemoteResult = sos_protocol::RemoteResult<Error>;

/// Sync result.
pub type SyncResult = sos_protocol::SyncResult<Error>;

/// Result type for the client module.
pub(crate) type Result<T> = std::result::Result<T, error::Error>;

pub use sos_protocol::is_offline;
