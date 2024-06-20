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

pub mod client;
mod error;

// FIXME: remove this
pub use sos_protocol as protocol;

/// Result type for the network module.
pub type Result<T> = std::result::Result<T, error::Error>;
pub use error::Error;

pub use reqwest;
pub use sos_sdk as sdk;
