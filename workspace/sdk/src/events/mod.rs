//! Log and sync events.

mod audit;
mod change;
mod event;
mod log;
mod read;
mod types;
mod write;

pub use self::log::{EventLogFile, EventRecord, EventReducer};
pub use audit::{
    AuditData, AuditEvent, AuditLogFile, AuditProvider, LogFlags,
};
pub use change::{ChangeAction, ChangeEvent, ChangeNotification};
pub use event::Event;
pub use read::ReadEvent;
pub use types::EventKind;
pub use write::WriteEvent;

/// Patch wraps a changeset of events to be sent across the network.
#[derive(Clone, Debug, Default)]
pub struct Patch(pub Vec<EventRecord>);
