//! Event for modifications to external files.
use super::{EventKind, LogEvent};
use crate::{ExternalFile, ExternalFileName, SecretPath};

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
    CreateFile(SecretPath, ExternalFileName),
    /// File was moved.
    MoveFile {
        /// File name.
        name: ExternalFileName,
        /// From identifiers.
        from: SecretPath,
        /// Destination identifiers.
        dest: SecretPath,
    },
    /// File was deleted.
    DeleteFile(SecretPath, ExternalFileName),
}

impl From<ExternalFile> for FileEvent {
    fn from(value: ExternalFile) -> Self {
        let (path, name) = value.into();
        FileEvent::CreateFile(path, name)
    }
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
