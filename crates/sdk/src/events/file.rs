//! Event for modifications to external files.
use super::{EventKind, LogEvent};
use crate::storage::files::{ExternalFileName, FileOwner};

/// File event records changes to external files
///
/// There is no update file event because files
/// are content-addressable by SHA256 digest so
/// changing a file's contents results in a
/// delete and create.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub enum FileEvent {
    #[default]
    #[doc(hidden)]
    Noop,
    /// File was created.
    CreateFile(FileOwner, ExternalFileName),
    /// File was moved.
    MoveFile {
        /// File name.
        name: ExternalFileName,
        /// From identifiers.
        from: FileOwner,
        /// Destination identifiers.
        dest: FileOwner,
    },
    /// File was deleted.
    DeleteFile(FileOwner, ExternalFileName),
}

impl LogEvent for FileEvent {
    fn event_kind(&self) -> EventKind {
        match self {
            Self::Noop => EventKind::Noop,
            Self::CreateFile(_, _) => EventKind::CreateFile,
            Self::MoveFile { .. } => EventKind::MoveFile,
            Self::DeleteFile(_, _) => EventKind::DeleteFile,
        }
    }
}
