use super::Error;
use crate::client::{CancelReason, Result};
use async_trait::async_trait;
use sos_sdk::{
    prelude::Address,
    storage,
    sync::{
        ChangeSet, DeviceDiff, Origin, SyncOptions, SyncPacket, SyncStatus,
        UpdateSet,
    },
};
use std::path::Path;

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
    /// Origin of the remote server.
    fn origin(&self) -> &Origin;

    /// Check if an account already exists.
    async fn account_exists(&self, account_id: &Address) -> Result<bool>;

    /// Create a new account.
    async fn create_account(&self, account: &ChangeSet) -> Result<()>;

    /// Update an account.
    async fn update_account(&self, account: &UpdateSet) -> Result<()>;

    /// Fetch an account from a remote server.
    async fn fetch_account(&self) -> Result<ChangeSet>;

    /// Sync status on remote, the result is `None` when the
    /// account does not exist.
    async fn sync_status(&self) -> Result<Option<SyncStatus>>;

    /// Sync with a remote.
    async fn sync(&self, packet: &SyncPacket) -> Result<SyncPacket>;

    /// Patch the device event log.
    #[cfg(feature = "device")]
    async fn patch_devices(&self, diff: &DeviceDiff) -> Result<()>;

    /// Send a file.
    #[cfg(feature = "files")]
    async fn upload_file(
        &self,
        file_info: &storage::files::ExternalFile,
        path: &Path,
        progress: crate::client::ProgressChannel,
        cancel: tokio::sync::watch::Receiver<CancelReason>,
    ) -> Result<http::StatusCode>;

    /// Receive a file.
    #[cfg(feature = "files")]
    async fn download_file(
        &self,
        file_info: &storage::files::ExternalFile,
        path: &Path,
        progress: crate::client::ProgressChannel,
        cancel: tokio::sync::watch::Receiver<CancelReason>,
    ) -> Result<http::StatusCode>;

    /// Delete a file on the remote server.
    #[cfg(feature = "files")]
    async fn delete_file(
        &self,
        file_info: &storage::files::ExternalFile,
    ) -> Result<http::StatusCode>;

    /// Move a file on the remote server.
    #[cfg(feature = "files")]
    async fn move_file(
        &self,
        from: &storage::files::ExternalFile,
        to: &storage::files::ExternalFile,
    ) -> Result<http::StatusCode>;

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
    ) -> Result<storage::files::FileTransfersSet>;
}
