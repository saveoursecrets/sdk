//! Server storage for a backend target.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::large_enum_variant)]

mod error;

mod database;
mod filesystem;
pub mod server_helpers;
mod storage;
mod sync;
mod traits;

pub use database::SharedFolderEvents;
pub use error::Error;
pub use storage::ServerStorage;
pub use traits::ServerAccountStorage;

/// Result type for the server module.
pub(crate) type Result<T> = std::result::Result<T, Error>;
