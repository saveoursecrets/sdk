//! Core types and constants for the Save Our Secrets SDK.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

pub mod commit;
pub mod constants;
mod error;
mod origin;

pub use error::Error;
pub use origin::Origin;

pub use rs_merkle as merkle;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;
