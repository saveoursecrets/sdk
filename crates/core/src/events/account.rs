//! Event for operations at the account level.
use super::{EventKind, LogEvent};
use crate::VaultId;
use serde::{Deserialize, Serialize};

/// Events generated in the context of an account.
#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AccountEvent {
    #[default]
    #[doc(hidden)]
    Noop,

    /// Account was renamed.
    RenameAccount(String),

    /// Identity folder was updated.
    ///
    /// This event happens when a the identity folder
    /// cipher changed, the account password changed
    /// or if the identity folder was compacted.
    ///
    /// This event is destructive as it re-writes
    /// the folder event log.
    ///
    /// Buffer is a vault.
    UpdateIdentity(#[serde(skip)] Vec<u8>),

    /// Create folder.
    ///
    /// Buffer is a head-only vault.
    CreateFolder(VaultId, #[serde(skip)] Vec<u8>),

    /// Rename a folder.
    RenameFolder(VaultId, String),

    /// Folder was updated.
    ///
    /// This event happens when a folder is imported and
    /// overwrites an existing folder.
    ///
    /// This event is destructive as it re-writes
    /// the folder event log.
    ///
    /// Buffer is a vault.
    UpdateFolder(VaultId, #[serde(skip)] Vec<u8>),

    /// Folder events were compacted.
    ///
    /// This event is destructive as it re-writes
    /// the folder event log.
    ///
    /// Buffer is a vault.
    CompactFolder(VaultId, #[serde(skip)] Vec<u8>),

    /// Change folder password.
    ///
    /// This event is destructive as it re-writes
    /// the folder event log.
    ///
    /// Buffer is a vault.
    ChangeFolderPassword(VaultId, #[serde(skip)] Vec<u8>),

    /// Delete folder.
    DeleteFolder(VaultId),
}

impl AccountEvent {
    /// Folder identifier for the event.
    pub fn folder_id(&self) -> Option<VaultId> {
        match self {
            AccountEvent::RenameAccount(_) => None,
            AccountEvent::UpdateIdentity(_) => None,
            AccountEvent::CreateFolder(vault_id, _)
            | AccountEvent::UpdateFolder(vault_id, _)
            | AccountEvent::CompactFolder(vault_id, _)
            | AccountEvent::ChangeFolderPassword(vault_id, _) => {
                Some(*vault_id)
            }
            AccountEvent::RenameFolder(vault_id, _) => Some(*vault_id),
            AccountEvent::DeleteFolder(vault_id) => Some(*vault_id),
            AccountEvent::Noop => None,
        }
    }
}

impl LogEvent for AccountEvent {
    fn event_kind(&self) -> EventKind {
        match self {
            Self::Noop => EventKind::Noop,
            Self::RenameAccount(_) => EventKind::RenameAccount,
            Self::UpdateIdentity(_) => EventKind::UpdateIdentity,
            Self::CreateFolder(_, _) => EventKind::CreateVault,
            Self::RenameFolder(_, _) => EventKind::SetVaultName,
            Self::CompactFolder(_, _) => EventKind::CompactVault,
            Self::UpdateFolder(_, _) => EventKind::UpdateVault,
            Self::ChangeFolderPassword(_, _) => EventKind::ChangePassword,
            Self::DeleteFolder(_) => EventKind::DeleteVault,
        }
    }
}
