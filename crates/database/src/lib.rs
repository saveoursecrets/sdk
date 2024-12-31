//! Database storage layer for the [Save Our Secrets](https://saveoursecrets.com) SDK.
pub mod db;
mod error;
pub mod importer;
pub mod migrations;
pub mod storage;

pub use error::Error;

#[cfg(feature = "search")]
pub mod search;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;
