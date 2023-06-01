//! Encoding of all operations.

use serde::{Deserialize, Serialize};

use crate::vault::{secret::SecretId, VaultId};

use super::{EventKind, ReadEvent, WriteEvent};

/// Events generated when reading or writing.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum Event<'a> {
    /// Read vault operations.
    Read(VaultId, ReadEvent),

    /// Write vault operations.
    Write(VaultId, WriteEvent<'a>),

    /// Move a secret between vaults.
    MoveSecret {
        /// Moved from vault.
        from_vault_id: VaultId,
        /// Old secret identifier.
        from_secret_id: SecretId,
        /// Moved to vault.
        to_vault_id: VaultId,
        /// New secret identifier.
        to_secret_id: SecretId,
    },
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
            Self::MoveSecret { .. } => EventKind::MoveSecret,
        }
    }

    /// Convert to an owned write event.
    ///
    /// # Panics
    ///
    /// If the event is not a write event.
    pub fn into_owned(self) -> (VaultId, WriteEvent<'static>) {
        match self {
            Self::Write(vault_id, event) => (vault_id, event.into_owned()),
            _ => panic!("not a write event"),
        }
    }
}

impl From<(VaultId, WriteEvent<'static>)> for Event<'static> {
    fn from(value: (VaultId, WriteEvent<'static>)) -> Self {
        Self::Write(value.0, value.1)
    }
}
