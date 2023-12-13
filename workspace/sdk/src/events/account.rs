//! Event for operations at the account level.
use super::{EventKind, LogEvent};
use crate::vault::VaultId;
use serde::{Deserialize, Serialize};

/// Events generated in the context of an account.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum AccountEvent {
    #[default]
    #[doc(hidden)]
    Noop,

    /// Create folder.
    ///
    /// Buffer is a head-only vault.
    CreateFolder(VaultId, Vec<u8>),

    /// Folder was updated.
    ///
    /// This event happens when a folder is imported and
    /// overwrites an existing folder.
    ///
    /// This event is destructive as it re-writes
    /// the folder event log.
    ///
    /// Buffer is a vault.
    UpdateFolder(VaultId, Vec<u8>),

    /// Folder events were compacted.
    ///
    /// This event is destructive as it re-writes
    /// the folder event log.
    CompactFolder(VaultId),

    /// Change folder password.
    ///
    /// This event is destructive as it re-writes
    /// the folder event log.
    ChangeFolderPassword(VaultId),

    /// Delete folder.
    DeleteFolder(VaultId),
}

impl LogEvent for AccountEvent {
    fn event_kind(&self) -> EventKind {
        match self {
            Self::Noop => EventKind::Noop,
            Self::CreateFolder(_, _) => EventKind::CreateVault,
            Self::CompactFolder(_) => EventKind::CompactVault,
            Self::UpdateFolder(_, _) => EventKind::UpdateVault,
            Self::ChangeFolderPassword(_) => EventKind::ChangePassword,
            Self::DeleteFolder(_) => EventKind::DeleteVault,
        }
    }
}
