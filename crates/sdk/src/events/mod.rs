//! Events represent changes to accounts, folders and files.
//!
//! Events may be appended to *event log* files for persistence.
//!
//! Event logs maintain an in-memory merkle tree of commits to
//! enable syncing of data between devices.
//!
//! They are also used for some read events to maintain
//! an audit trail of actions.

mod account;
#[cfg(feature = "device")]
mod device;
mod event;
#[cfg(feature = "files")]
mod file;
mod log;
mod read;
mod types;
mod write;

pub use self::log::{
    AccountEventLog, DiscData, DiscEventLog, DiscLog, EventLogExt,
    EventRecord, FolderEventLog, FolderReducer, MemoryData, MemoryEventLog,
    MemoryFolderLog, MemoryLog,
};

#[cfg(feature = "device")]
pub use self::log::{DeviceEventLog, DeviceReducer};

#[cfg(feature = "files")]
pub use self::log::FileEventLog;

#[cfg(feature = "files")]
pub use self::log::FileReducer;

pub use account::AccountEvent;
#[cfg(feature = "device")]
pub use device::DeviceEvent;
pub use event::Event;
#[cfg(feature = "files")]
pub use file::FileEvent;
pub use read::ReadEvent;
pub use types::EventKind;
pub use write::WriteEvent;

/// Trait for events that can be written to an event log..
pub trait LogEvent {
    /// Get the event kind for this event.
    fn event_kind(&self) -> EventKind;
}