#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Sync protocol implementation types and traits.
mod auto_merge;
mod error;
// mod primitives;
mod remote;

pub use error::Error;

pub use auto_merge::*;
// pub use primitives::*;
pub use remote::*;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
