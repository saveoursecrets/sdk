//! Event for modifications to external files.
use super::{EventKind, LogEvent};
use crate::vault::{secret::SecretId, VaultId};

/// File event records changes to external files
///
/// There is no update file event because files
/// are content-addressable by SHA256 digest so
/// changing a file's contents results in a
/// delete and create.
#[derive(Default)]
pub enum FileEvent {
    #[default]
    #[doc(hidden)]
    Noop,
    /// File was created.
    CreateFile(VaultId, SecretId, String),
    /// File was deleted.
    DeleteFile(VaultId, SecretId, String),
}

impl LogEvent for FileEvent {
    fn event_kind(&self) -> EventKind {
        todo!();

        /*
        match self {
            Self::Noop => EventKind::Noop,
            Self::CreateFolder(_) => EventKind::CreateVault,
            Self::UpdateFolder(_) => EventKind::UpdateVault,
            Self::DeleteFolder(_) => EventKind::DeleteVault,
        }
        */
    }
}
