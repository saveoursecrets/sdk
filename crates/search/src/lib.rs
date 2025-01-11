#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Search provides an in-memory index for secret meta data.
mod error;
mod search;

pub use error::Error;
pub use search::*;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
