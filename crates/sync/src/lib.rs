#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Core types and traits for sync and merge operations.
mod error;
mod traits;
mod types;

pub use error::Error;

pub use traits::*;
pub use types::*;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;
