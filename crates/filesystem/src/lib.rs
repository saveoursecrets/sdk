#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Events logs backed by the file system.
mod encoding;
mod error;
mod event_log;
pub mod formats;
#[cfg(feature = "preferences")]
mod preferences;
mod server_origins;
#[cfg(feature = "system-messages")]
mod system_messages;
mod vault_writer;

pub use error::Error;
#[cfg(feature = "preferences")]
pub use preferences::*;
pub use server_origins::ServerOrigins;
#[cfg(feature = "system-messages")]
pub use system_messages::SystemMessagesProvider;
pub use vault_writer::VaultFileWriter;

/// AccessPoint that mirrors changes to a vault on disc.
pub type FileSystemAccessPoint<E> = sos_vault::AccessPoint<E>;

pub use event_log::{
    AccountEventLog, DeviceEventLog, FileSystemEventLog, FolderEventLog,
};

#[cfg(feature = "files")]
pub use event_log::FileEventLog;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
