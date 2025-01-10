pub mod compact;
mod error;
mod event_log;
mod folder;
mod gate_keeper;
pub mod reducers;

pub use error::Error;

pub use event_log::{BackendEventLog, BackendFolderEventLog};
pub use folder::Folder;
pub use gate_keeper::BackendGateKeeper;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
