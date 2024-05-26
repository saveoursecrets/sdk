use super::Error;
use async_trait::async_trait;
use sos_sdk::{
    storage,
    sync::{
        ChangeSet, DeviceDiff, Origin, SyncOptions, SyncPacket, SyncStatus,
        UpdateSet,
    },
};
use std::{path::Path, sync::Arc};

/// Error type that can be returned from a sync operation.
pub type SyncError = sos_sdk::sync::SyncError<Error>;

/// Trait for types that can sync accounts with a remote.
#[async_trait]
pub trait RemoteSync {
    /// Perform a full sync of the account using
    /// the default options.
    ///
    /// If the account does not exist on the remote
    /// server the account will be created and
    /// [RemoteSync::sync_file_transfers] will be called
    /// to ensure the transfers queue is synced.
    async fn sync(&self) -> Option<SyncError>;

    /// Perform a full sync of the account
    /// using the given options.
    ///
    /// See the documentation for [RemoteSync::sync] for more details.
    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> Option<SyncError>;

    /// Sync file transfers.
    ///
    /// Updates the file transfers queue with any pending
    /// uploads or downloads by comparing the local file
    /// state with the file state on remote server(s).
    async fn sync_file_transfers(
        &self,
        options: &SyncOptions,
    ) -> Option<SyncError>;

    /// Patch the device log on the remote.
    async fn patch_devices(&self, options: &SyncOptions)
        -> Option<SyncError>;

    /// Force update an account on remote servers.
    ///
    /// Should be called after making destructive
    /// changes to an account's folders. For example, if
    /// the encryption cipher has been changed, a folder
    /// password was changed or folder(s) were compacted.
    async fn force_update(
        &self,
        account_data: &UpdateSet,
        options: &SyncOptions,
    ) -> Option<SyncError>;
}

/// Client that can synchronize with a remote server.
#[async_trait]
pub trait SyncClient {
    /// Errors produced by the client.
    type Error: std::fmt::Debug;

    /// Origin of the remote server.
    fn origin(&self) -> &Origin;

    /// Create a new account.
    async fn create_account(
        &self,
        account: &ChangeSet,
    ) -> std::result::Result<(), Self::Error>;

    /// Update an account.
    async fn update_account(
        &self,
        account: &UpdateSet,
    ) -> std::result::Result<(), Self::Error>;

    /// Fetch an account from a remote server.
    async fn fetch_account(
        &self,
    ) -> std::result::Result<ChangeSet, Self::Error>;

    /// Sync status on remote, the result is `None` when the
    /// account does not exist.
    async fn sync_status(
        &self,
    ) -> std::result::Result<Option<SyncStatus>, Self::Error>;

    /// Sync with a remote.
    async fn sync(
        &self,
        packet: &SyncPacket,
    ) -> std::result::Result<SyncPacket, Self::Error>;

    /// Patch the device event log.
    #[cfg(feature = "device")]
    async fn patch_devices(
        &self,
        diff: &DeviceDiff,
    ) -> std::result::Result<(), Self::Error>;

    /// Send a file.
    #[cfg(feature = "files")]
    async fn upload_file(
        &self,
        file_info: &storage::files::ExternalFile,
        path: &Path,
        progress: Arc<storage::files::ProgressChannel>,
    ) -> std::result::Result<http::StatusCode, Self::Error>;

    /// Receive a file.
    #[cfg(feature = "files")]
    async fn download_file(
        &self,
        file_info: &storage::files::ExternalFile,
        path: &Path,
        progress: Arc<storage::files::ProgressChannel>,
    ) -> std::result::Result<http::StatusCode, Self::Error>;

    /// Delete a file on the remote server.
    #[cfg(feature = "files")]
    async fn delete_file(
        &self,
        file_info: &storage::files::ExternalFile,
    ) -> std::result::Result<http::StatusCode, Self::Error>;

    /// Move a file on the remote server.
    #[cfg(feature = "files")]
    async fn move_file(
        &self,
        from: &storage::files::ExternalFile,
        to: &storage::files::ExternalFile,
    ) -> std::result::Result<http::StatusCode, Self::Error>;

    /// Compare local files with a remote server.
    ///
    /// Used to build a transfer queue that will eventually ensure
    /// external files are in sync.
    ///
    /// Comparing sets of files is expensive as both local and remote
    /// need to read the external files state from disc so only use this
    /// when necessary.
    #[cfg(feature = "files")]
    async fn compare_files(
        &self,
        local_files: &storage::files::FileSet,
    ) -> std::result::Result<storage::files::FileTransfersSet, Self::Error>;
}
