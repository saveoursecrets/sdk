#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
#![allow(clippy::large_enum_variant)]

//! Server storage for a backend target.
mod error;

mod database;
mod filesystem;
pub mod server_helpers;
mod storage;
mod sync;
mod traits;

pub use error::Error;
pub use storage::ServerStorage;
pub use traits::ServerAccountStorage;

/// Result type for the server module.
pub(crate) type Result<T> = std::result::Result<T, Error>;
