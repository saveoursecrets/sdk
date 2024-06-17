//! Manage pending file transfer operations.
use crate::{
    events::FileEvent,
    storage::files::{ExternalFile, FileMutationEvent},
};
use indexmap::IndexSet;

/// Set of files built from the state on disc.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileSet(pub IndexSet<ExternalFile>);

/// Sets of files that should be uploaded and
/// downloaded from a remote server.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileTransfersSet {
    /// Files that exist on local but not on remote.
    pub uploads: FileSet,
    /// Files that exist on remote but not on local.
    pub downloads: FileSet,
}

/// Operations for file transfers.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum TransferOperation {
    /// Upload a file.
    Upload,
    /// Download a file.
    Download,
    /// Delete a file.
    Delete,
    /// Move a file.
    Move(ExternalFile),
}

impl From<&FileMutationEvent> for (ExternalFile, TransferOperation) {
    fn from(value: &FileMutationEvent) -> Self {
        match value {
            FileMutationEvent::Create { event, .. } => event.into(),
            FileMutationEvent::Move(event) => event.into(),
            FileMutationEvent::Delete(event) => event.into(),
        }
    }
}

impl From<&FileEvent> for (ExternalFile, TransferOperation) {
    fn from(value: &FileEvent) -> Self {
        match value {
            FileEvent::CreateFile(vault_id, secret_id, file_name) => (
                ExternalFile::new(*vault_id, *secret_id, *file_name),
                TransferOperation::Upload,
            ),
            FileEvent::DeleteFile(vault_id, secret_id, file_name) => (
                ExternalFile::new(*vault_id, *secret_id, *file_name),
                TransferOperation::Delete,
            ),
            FileEvent::MoveFile { name, from, dest } => (
                ExternalFile::new(from.0, from.1, *name),
                TransferOperation::Move(ExternalFile::new(
                    dest.0, dest.1, *name,
                )),
            ),
            _ => panic!("attempt to convert noop file event"),
        }
    }
}
