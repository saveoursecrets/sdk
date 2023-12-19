//! Encoding of all operations.

use super::AccountEvent;
use super::{EventKind, LogEvent, ReadEvent, WriteEvent};
use crate::{vault::VaultId, Error, Result, signer::ecdsa::Address};
use serde::{Deserialize, Serialize};

#[cfg(feature = "files")]
use super::FileEvent;

/// Events generated when reading or writing.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum Event {
    /// Create account event.
    CreateAccount(Address),

    /// Account changes.
    Account(AccountEvent),

    /// Combined event that encapsulates an account
    /// event with a folder write event.
    ///
    /// Typically used to combine the folder creation
    /// (which includes the secure access key) with the
    /// create vault event which contains the vault buffer.
    Folder(AccountEvent, WriteEvent),

    #[cfg(feature = "files")]
    /// File event.
    File(FileEvent),

    /// Read folder operations.
    Read(VaultId, ReadEvent),

    /// Write folder operations.
    Write(VaultId, WriteEvent),

    /// Move secret operation.
    MoveSecret(ReadEvent, WriteEvent, WriteEvent),

    /// Delete account event.
    DeleteAccount(Address),
}

impl Event {
    /// Get the event kind for this event.
    pub fn event_kind(&self) -> EventKind {
        match self {
            Self::CreateAccount(_) => EventKind::CreateAccount,
            Self::Account(event) => event.event_kind(),
            Self::Folder(event, _) => event.event_kind(),
            #[cfg(feature = "files")]
            Self::File(event) => event.event_kind(),
            Self::Read(_, event) => event.event_kind(),
            Self::Write(_, event) => event.event_kind(),
            Self::MoveSecret(_, _, _) => EventKind::MoveSecret,
            Self::DeleteAccount(_) => EventKind::DeleteAccount,
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
