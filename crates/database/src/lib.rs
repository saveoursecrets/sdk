#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Database storage layer for the [Save Our Secrets](https://saveoursecrets.com) SDK.
#[cfg(all(feature = "archive", feature = "sqlite"))]
pub mod archive;
#[cfg(all(feature = "audit", feature = "sqlite"))]
pub mod audit_provider;
#[cfg(feature = "sqlite")]
pub mod db;
#[cfg(feature = "sqlite")]
pub mod event_log;
#[cfg(feature = "sqlite")]
pub mod migrations;
#[cfg(all(feature = "sqlite", feature = "preferences"))]
mod preferences;
#[cfg(all(feature = "sqlite", feature = "system-messages"))]
mod system_messages;

#[cfg(feature = "sqlite")]
mod server_origins;

#[cfg(feature = "sqlite")]
pub mod upgrader;

#[cfg(feature = "sqlite")]
mod vault_writer;

#[cfg(feature = "sqlite")]
pub use event_log::{
    AccountEventLog, DatabaseEventLog, DeviceEventLog, FolderEventLog,
};

#[cfg(all(feature = "sqlite", feature = "preferences"))]
pub use preferences::PreferenceProvider;

#[cfg(all(feature = "sqlite", feature = "system-messages"))]
pub use system_messages::SystemMessagesProvider;

#[cfg(feature = "sqlite")]
pub use server_origins::ServerOrigins;

#[cfg(feature = "sqlite")]
pub use vault_writer::VaultDatabaseWriter;

#[cfg(all(feature = "sqlite", feature = "files"))]
pub use event_log::FileEventLog;

mod error;
pub use async_sqlite;
pub use error::Error;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
