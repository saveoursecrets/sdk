//! Event for operations at the account level.

use super::{EventKind, LogEvent};
use crate::{crypto::SecureAccessKey, vault::VaultId, Error, Result};

/// Events generated in the context of an account.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub enum AccountEvent {
    #[default]
    #[doc(hidden)]
    Noop,

    /// Create folder.
    CreateFolder(VaultId, SecureAccessKey),

    /// Folder events were compacted.
    CompactFolder(VaultId),

    /*
    /// Update folder name.
    UpdateFolderName(VaultId, String),
    */

    /// Change folder password.
    ChangeFolderPassword(VaultId, SecureAccessKey),

    /// Delete folder.
    DeleteFolder(VaultId),
}

impl LogEvent for AccountEvent {
    fn event_kind(&self) -> EventKind {
        match self {
            Self::Noop => EventKind::Noop,
            Self::CreateFolder(_, _) => EventKind::CreateVault,
            Self::CompactFolder(_) => EventKind::CompactVault,
            //Self::UpdateFolderName(_, _) => EventKind::SetVaultName,
            Self::ChangeFolderPassword(_, _) => EventKind::ChangePassword,
            Self::DeleteFolder(_) => EventKind::DeleteVault,
        }
    }
}
