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
    CreateFolder(VaultId),

    /// Folder was updated.
    ///
    /// This event happens when a folder is imported and
    /// overwrites an existing folder.
    ///
    /// This event is destructive as it re-writes
    /// the folder event log.
    UpdateFolder(VaultId),

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
            Self::CreateFolder(_) => EventKind::CreateVault,
            Self::CompactFolder(_) => EventKind::CompactVault,
            Self::UpdateFolder(_) => EventKind::UpdateVault,
            Self::ChangeFolderPassword(_) => EventKind::ChangePassword,
            Self::DeleteFolder(_) => EventKind::DeleteVault,
        }
    }
}
