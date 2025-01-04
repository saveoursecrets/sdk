//! Database storage layer for the [Save Our Secrets](https://saveoursecrets.com) SDK.
#[cfg(feature = "sqlite")]
pub mod db;
mod error;
#[cfg(feature = "sqlite")]
pub mod importer;
#[cfg(feature = "sqlite")]
pub mod migrations;

#[cfg(feature = "files")]
pub mod files;

pub use error::{Error, StorageError};

#[cfg(feature = "search")]
pub mod search;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
