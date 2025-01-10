#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Backend database and file system storage.
mod access_point;
pub mod compact;
mod error;
mod event_log;
mod folder;
pub mod reducers;
#[cfg(feature = "search")]
pub mod search;
mod vault_writer;

pub use error::Error;

pub use access_point::BackendAccessPoint as AccessPoint;
pub use event_log::{
    BackendAccountEventLog as AccountEventLog,
    BackendDeviceEventLog as DeviceEventLog, BackendEventLog,
    BackendFolderEventLog as FolderEventLog,
};
pub use folder::Folder;
pub use vault_writer::VaultWriter;

#[cfg(feature = "files")]
pub use event_log::BackendFileEventLog as FileEventLog;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
