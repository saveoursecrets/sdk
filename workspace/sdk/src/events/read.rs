//! Read operations.

use serde::{Deserialize, Serialize};
use crate::vault::secret::SecretId;
use super::EventKind;

/// Read operations.
#[derive(Default, Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub enum ReadEvent {
    /// Default variant, should never be used.
    ///
    /// We need a variant so we can implement the Default
    /// trait which is required for decoding.
    #[default]
    Noop,

    /// Event used to indicate that a vault was read.
    ReadVault,

    /// Event used to indicate that a secret has been read.
    ReadSecret(SecretId),
}

impl ReadEvent {
    /// Get the event kind for this event.
    pub fn event_kind(&self) -> EventKind {
        match self {
            ReadEvent::Noop => EventKind::Noop,
            ReadEvent::ReadVault => EventKind::ReadVault,
            ReadEvent::ReadSecret(_) => EventKind::ReadSecret,
        }
    }
}
