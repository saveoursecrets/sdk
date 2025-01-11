#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Database storage layer for the [Save Our Secrets](https://saveoursecrets.com) SDK.
#[cfg(feature = "sqlite")]
pub mod db;
#[cfg(feature = "sqlite")]
pub mod event_log;
#[cfg(feature = "sqlite")]
pub mod importer;
#[cfg(feature = "sqlite")]
pub mod migrations;

#[cfg(feature = "sqlite")]
mod vault_writer;

#[cfg(feature = "sqlite")]
pub use event_log::DatabaseEventLog;
#[cfg(feature = "sqlite")]
pub use vault_writer::VaultDatabaseWriter;

#[cfg(feature = "files")]
pub mod files;

mod error;
pub use async_sqlite;
pub use error::{Error, StorageError};

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
