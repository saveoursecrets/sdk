#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Backend database and file system storage.
mod access_point;
#[cfg(feature = "audit")]
pub mod audit;
pub mod compact;
mod error;
mod event_log;
mod folder;
#[cfg(feature = "preferences")]
mod preferences;
mod server_origins;
#[cfg(feature = "system-messages")]
mod system_messages;
mod vault_writer;

pub use error::{Error, StorageError};
pub use sos_database as database;
pub use sos_filesystem::write_exclusive;
pub use sos_reducers as reducers;

pub use access_point::BackendAccessPoint as AccessPoint;
pub use event_log::{
    BackendAccountEventLog as AccountEventLog,
    BackendDeviceEventLog as DeviceEventLog, BackendEventLog,
    BackendFolderEventLog as FolderEventLog,
};
pub use folder::Folder;
#[cfg(feature = "preferences")]
pub use preferences::BackendPreferences as Preferences;
pub use server_origins::ServerOrigins;
#[cfg(feature = "system-messages")]
pub use system_messages::SystemMessages;
pub use vault_writer::VaultWriter;

#[cfg(feature = "files")]
pub use event_log::BackendFileEventLog as FileEventLog;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
