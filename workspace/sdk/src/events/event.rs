//! Encoding of all operations.

use super::{AuditEvent, EventKind, ReadEvent, WriteEvent};
use crate::{vault::VaultId, Error, Result, signer::ecdsa::Address};
use serde::{Deserialize, Serialize};

/// Events generated in the context of an account.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub enum AccountEvent {
    #[default]
    #[doc(hidden)]
    Noop,

    /// Create folder.
    CreateFolder(VaultId, Vec<u8>),

    /// Update folder.
    UpdateFolder(VaultId, Vec<u8>),

    /// Delete folder.
    DeleteFolder(VaultId),
}

impl AccountEvent {
    /// Get the event kind for this event.
    pub fn event_kind(&self) -> EventKind {
        match self {
            Self::Noop => EventKind::Noop,
            Self::CreateFolder(_, _) => EventKind::CreateVault,
            Self::UpdateFolder(_, _) => EventKind::UpdateVault,
            Self::DeleteFolder(_) => EventKind::DeleteVault,
        }
    }
}

/// Events generated when reading or writing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Event<'a> {
    /// Create account event.
    CreateAccount(AuditEvent),

    /// Account changes.
    Account(Address, AccountEvent),

    /// Read vault operations.
    Read(VaultId, ReadEvent),

    /// Write vault operations.
    Write(VaultId, WriteEvent<'a>),

    /// Move secret operation.
    MoveSecret(ReadEvent, WriteEvent<'a>, WriteEvent<'a>),

    /// Delete account event.
    DeleteAccount(AuditEvent),
}

impl Event<'_> {
    /*
    /// Determine if this payload would mutate state.
    ///
    /// Some payloads are purely for auditing and do not
    /// mutate any data.
    pub fn is_mutation(&self) -> bool {
        !matches!(self, Self::Write(_, _))
    }
    */

    /// Get the event kind for this event.
    pub fn event_kind(&self) -> EventKind {
        match self {
            Self::CreateAccount(event) => event.event_kind(),
            Self::Account(_, event) => event.event_kind(),
            Self::Read(_, event) => event.event_kind(),
            Self::Write(_, event) => event.event_kind(),
            Self::MoveSecret(_, _, _) => EventKind::MoveSecret,
            Self::DeleteAccount(event) => event.event_kind(),
        }
    }
}

impl From<(VaultId, WriteEvent<'static>)> for Event<'static> {
    fn from(value: (VaultId, WriteEvent<'static>)) -> Self {
        Self::Write(value.0, value.1)
    }
}

// Convert to an owned write event.
impl<'a> TryFrom<Event<'a>> for (VaultId, WriteEvent<'static>) {
    type Error = Error;
    fn try_from(value: Event<'a>) -> Result<Self> {
        match value {
            Event::Write(vault_id, event) => {
                Ok((vault_id, event.into_owned()))
            }
            _ => panic!("not a write event"),
        }
    }
}
