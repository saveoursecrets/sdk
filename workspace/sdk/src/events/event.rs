//! Encoding of all operations.

use serde::{Deserialize, Serialize};

use crate::vault::VaultId;

use super::{EventKind, ReadEvent, WriteEvent};

/// Events generated when reading or writing.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum Event<'a> {
    /// Read vault operations.
    Read(VaultId, ReadEvent),

    /// Write vault operations.
    Write(VaultId, WriteEvent<'a>),
}

impl Event<'_> {
    /// Determine if this payload would mutate state.
    ///
    /// Some payloads are purely for auditing and do not
    /// mutate any data.
    pub fn is_mutation(&self) -> bool {
        !matches!(self, Self::Write(_, _))
    }

    /// Get the event kind for this event.
    pub fn event_kind(&self) -> EventKind {
        match self {
            Self::Read(_, event) => event.event_kind(),
            Self::Write(_, event) => event.event_kind(),
        }
    }
}
