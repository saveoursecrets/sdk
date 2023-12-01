//! Log and sync events.

use crate::Result;
use binary_stream::futures::Decodable;

#[cfg(feature = "account")]
mod account;
mod audit;
mod change;
mod event;
mod file;
mod log;
mod read;
mod types;
mod write;

#[cfg(feature = "account")]
pub use self::log::AccountEventLog;

pub use self::log::{
    EventLogFile, EventRecord, EventReducer, FolderEventLog,
};

#[cfg(feature = "files")]
pub use self::log::FileEventLog;

#[cfg(feature = "account")]
pub use account::AccountEvent;
pub use audit::{
    AuditData, AuditEvent, AuditLogFile, AuditProvider, LogFlags,
};
pub use change::{ChangeAction, ChangeEvent, ChangeNotification};
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
