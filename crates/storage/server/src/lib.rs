#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Server storage backed by the file system.
mod error;

pub mod filesystem;
pub mod server_helpers;
mod storage;
mod traits;

pub use error::Error;
pub use storage::ServerStorage;
pub use traits::ServerAccountStorage;

/// Result type for the server module.
pub(crate) type Result<T> = std::result::Result<T, Error>;
