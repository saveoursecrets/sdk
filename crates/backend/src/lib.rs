pub mod compact;
mod error;
mod event_log;
mod folder;
mod gate_keeper;
pub mod reducers;
#[cfg(feature = "search")]
pub mod search;

pub use error::Error;

pub use event_log::{
    BackendAccountEventLog as AccountEventLog,
    BackendDeviceEventLog as DeviceEventLog,
    BackendFolderEventLog as FolderEventLog,
};
pub use event_log::{BackendEventLog, BackendFolderEventLog};
pub use folder::Folder;
pub use gate_keeper::BackendGateKeeper;

#[cfg(feature = "files")]
pub use event_log::BackendFileEventLog as FileEventLog;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
