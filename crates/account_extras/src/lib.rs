//! Extra functions for [local accounts](https://docs.rs/sos-account/latest/sos_account/) in the [Save Our Secrets](https://saveoursecrets.com) SDK.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod error;

/// Errors generated by the extras library.
pub use error::Error;

/// Result type for the extras library.
pub(crate) type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "security-report")]
pub mod security_report;

#[cfg(feature = "system-messages")]
pub mod system_messages;
