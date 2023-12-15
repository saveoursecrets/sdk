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
mod audit;
mod event;
#[cfg(feature = "files")]
mod file;
mod log;
mod read;
mod types;
mod write;

pub use self::log::{
    AccountEventLog, AccountReducer, DiscData, DiscEventLog, DiscLog,
    EventLogExt, EventRecord, EventReducer, FolderEventLog, MemoryData,
    MemoryEventLog, MemoryFolderLog, MemoryLog,
};

#[cfg(feature = "files")]
pub use self::log::FileEventLog;

pub use account::AccountEvent;
pub use audit::{
    AuditData, AuditEvent, AuditLogFile, AuditProvider, LogFlags,
};
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
