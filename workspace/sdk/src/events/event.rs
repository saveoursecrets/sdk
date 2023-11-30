//! Encoding of all operations.

use super::{AuditEvent, EventKind, LogEvent, ReadEvent, WriteEvent};
use crate::{vault::VaultId, Error, Result};

/// Events generated in the context of an account.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub enum AccountEvent {
    #[default]
    #[doc(hidden)]
    Noop,

    /// Create folder.
    CreateFolder(VaultId),

    /// Update folder.
    UpdateFolder(VaultId),

    /// Delete folder.
    DeleteFolder(VaultId),
}

impl LogEvent for AccountEvent {
    fn event_kind(&self) -> EventKind {
        match self {
            Self::Noop => EventKind::Noop,
            Self::CreateFolder(_) => EventKind::CreateVault,
            Self::UpdateFolder(_) => EventKind::UpdateVault,
            Self::DeleteFolder(_) => EventKind::DeleteVault,
        }
    }
}

/// Events generated when reading or writing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Event {
    /// Create account event.
    CreateAccount(AuditEvent),

    /// Account changes.
    Account(AccountEvent),

    /// Read folder operations.
    Read(VaultId, ReadEvent),

    /// Write folder operations.
    Write(VaultId, WriteEvent),

    /// Move secret operation.
    MoveSecret(ReadEvent, WriteEvent, WriteEvent),

    /// Delete account event.
    DeleteAccount(AuditEvent),
}

impl Event {
    /// Get the event kind for this event.
    pub fn event_kind(&self) -> EventKind {
        match self {
            Self::CreateAccount(event) => event.event_kind(),
            Self::Account(event) => event.event_kind(),
            Self::Read(_, event) => event.event_kind(),
            Self::Write(_, event) => event.event_kind(),
            Self::MoveSecret(_, _, _) => EventKind::MoveSecret,
            Self::DeleteAccount(event) => event.event_kind(),
        }
    }
}

impl From<(VaultId, WriteEvent)> for Event {
    fn from(value: (VaultId, WriteEvent)) -> Self {
        Self::Write(value.0, value.1)
    }
}

// Convert to an owned write event.
impl TryFrom<Event> for (VaultId, WriteEvent) {
    type Error = Error;
    fn try_from(value: Event) -> Result<Self> {
        match value {
            Event::Write(vault_id, event) => Ok((vault_id, event)),
            _ => panic!("not a write event"),
        }
    }
}
