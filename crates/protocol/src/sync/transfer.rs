//! Manage pending file transfer operations.
use crate::sdk::{
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

/// File and transfer information.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct FileOperation(pub ExternalFile, pub TransferOperation);

impl From<&FileMutationEvent> for FileOperation {
    fn from(value: &FileMutationEvent) -> Self {
        match value {
            FileMutationEvent::Create { event, .. } => event.into(),
            FileMutationEvent::Move(event) => event.into(),
            FileMutationEvent::Delete(event) => event.into(),
        }
    }
}

impl From<&FileEvent> for FileOperation {
    fn from(value: &FileEvent) -> Self {
        match value {
            FileEvent::CreateFile(owner, file_name) => FileOperation(
                ExternalFile::new(*owner, *file_name),
                TransferOperation::Upload,
            ),
            FileEvent::DeleteFile(owner, file_name) => FileOperation(
                ExternalFile::new(*owner, *file_name),
                TransferOperation::Delete,
            ),
            FileEvent::MoveFile { name, from, dest } => FileOperation(
                ExternalFile::new(*from, *name),
                TransferOperation::Move(ExternalFile::new(*dest, *name)),
            ),
            _ => panic!("attempt to convert noop file event"),
        }
    }
}
