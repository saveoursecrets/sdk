//! Types for file transfers.

/// Information about a cancellation.
#[derive(Default, Debug, Clone, Hash, Eq, PartialEq)]
pub enum CancelReason {
    /// Unknown reason.
    #[default]
    Unknown,
    /// Event loop is being shutdown.
    Shutdown,
    /// Websocket connection was closed.
    Closed,
    /// Cancellation was from a user interaction.
    UserCanceled,
    /// Aborted due to conflict with a subsequent operation.
    ///
    /// For example, a move or delete transfer operation must abort
    /// any existing upload or download.
    Aborted,
}

#[cfg(feature = "files")]
mod files {
    //! Manage pending file transfer operations.
    use crate::sdk::{
        events::FileEvent,
        storage::files::{ExternalFile, FileMutationEvent},
    };

    use crate::transfer::CancelReason;
    use async_trait::async_trait;
    use http::StatusCode;
    use indexmap::IndexSet;
    use std::path::Path;
    use tokio::sync::watch;

    /// Channel for upload and download progress notifications.
    pub type ProgressChannel = tokio::sync::mpsc::Sender<(u64, Option<u64>)>;

    /// Request to queue a file transfer.
    pub type FileTransferQueueRequest = Vec<FileOperation>;

    /// Sender to queue a file transfer.
    pub type FileTransferQueueSender =
        tokio::sync::broadcast::Sender<FileTransferQueueRequest>;

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

    /// Client that can synchronize files.
    #[async_trait]
    pub trait FileSyncClient {
        /// Error type for file sync client.
        type Error: std::error::Error + std::fmt::Debug;

        /// Send a file.
        async fn upload_file(
            &self,
            file_info: &ExternalFile,
            path: &Path,
            progress: ProgressChannel,
            cancel: watch::Receiver<CancelReason>,
        ) -> Result<StatusCode, Self::Error>;

        /// Receive a file.
        async fn download_file(
            &self,
            file_info: &ExternalFile,
            path: &Path,
            progress: ProgressChannel,
            cancel: watch::Receiver<CancelReason>,
        ) -> Result<StatusCode, Self::Error>;

        /// Delete a file on the remote server.
        async fn delete_file(
            &self,
            file_info: &ExternalFile,
        ) -> Result<StatusCode, Self::Error>;

        /// Move a file on the remote server.
        async fn move_file(
            &self,
            from: &ExternalFile,
            to: &ExternalFile,
        ) -> Result<StatusCode, Self::Error>;

        /// Compare local files with a remote server.
        ///
        /// Used to build a transfer queue that will eventually ensure
        /// external files are in sync.
        ///
        /// Comparing sets of files is expensive as both local and remote
        /// need to read the external files state from disc so only use this
        /// when necessary.
        async fn compare_files(
            &self,
            local_files: FileSet,
        ) -> Result<FileTransfersSet, Self::Error>;
    }
}

#[cfg(feature = "files")]
pub use files::*;
