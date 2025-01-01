//! Database storage layer for the [Save Our Secrets](https://saveoursecrets.com) SDK.
pub mod db;
mod error;
pub mod importer;
pub mod migrations;

#[cfg(feature = "files")]
pub mod files;

pub use error::{Error, StorageError};

#[cfg(feature = "search")]
pub mod search;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;
