#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::result_large_err)]

//! Database upgrader for the [Save Our Secrets](https://saveoursecrets.com) SDK.
#[cfg(feature = "archive")]
pub mod archive;
mod upgrader;

pub use upgrader::*;

mod error;
pub use error::Error;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
