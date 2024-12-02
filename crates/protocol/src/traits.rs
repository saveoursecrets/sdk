use crate::{
    CreateSet, DiffRequest, DiffResponse, MergeOutcome, Origin, PatchRequest,
    PatchResponse, ScanRequest, ScanResponse, SyncOptions, SyncPacket,
    SyncStatus, UpdateSet,
};
use async_trait::async_trait;
use sos_sdk::prelude::Address;

/// Channel for upload and download progress notifications.
pub type ProgressChannel = tokio::sync::mpsc::Sender<(u64, Option<u64>)>;

/// Result of a sync operation with a single remote.
#[derive(Debug)]
pub struct RemoteResult<E> {
    /// Origin of the remote.
    pub origin: Origin,
    /// Result of the sync operation.
    pub result: Result<Option<MergeOutcome>, E>,
}

/// Result of a sync operation.
#[derive(Debug)]
pub struct SyncResult<E> {
    /// Result of syncing with remote data sources.
    pub remotes: Vec<RemoteResult<E>>,
}

impl<E> Default for SyncResult<E> {
    fn default() -> Self {
        Self {
            remotes: Vec::new(),
        }
    }
}

impl<E> SyncResult<E> {
    /// Find the first sync error.
    pub fn first_error(self) -> Option<E> {
        self.remotes.into_iter().find_map(|res| {
            if res.result.is_err() {
                res.result.err()
            } else {
                None
            }
        })
    }

    /// Find the first sync error by reference.
    pub fn first_error_ref(&self) -> Option<&E> {
        self.remotes.iter().find_map(|res| {
            if let Err(e) = &res.result {
                Some(e)
            } else {
                None
            }
        })
    }

    /// Determine if the sync has one or more errors.
    pub fn has_error(&self) -> bool {
        self.remotes.iter().any(|r| r.result.is_err())
    }
}

/// Trait for types that can sync with a single remote.
#[async_trait]
pub trait RemoteSync {
    /// Error type for remote sync.
    type Error: std::error::Error + std::fmt::Debug;

    /// Perform a full sync of the account using
    /// the default options.
    ///
    /// If the account does not exist on the remote
    /// server the account will be created and
    /// [RemoteSync::sync_file_transfers] will be called
    /// to ensure the transfers queue is synced.
    async fn sync(&self) -> RemoteResult<Self::Error>;

    /// Perform a full sync of the account
    /// using the given options.
    ///
    /// See the documentation for [RemoteSync::sync] for more details.
    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> RemoteResult<Self::Error>;

    /// Sync file transfers.
    ///
    /// Updates the file transfers queue with any pending
    /// uploads or downloads by comparing the local file
    /// state with the file state on remote server(s).
    #[cfg(feature = "files")]
    async fn sync_file_transfers(&self) -> RemoteResult<Self::Error>;

    /// Force update an account on remote servers.
    ///
    /// Should be called after making destructive
    /// changes to an account's folders. For example, if
    /// the encryption cipher has been changed, a folder
    /// password was changed or folder(s) were compacted.
    async fn force_update(
        &self,
        account_data: UpdateSet,
    ) -> RemoteResult<Self::Error>;
}

/// Trait for types that can sync with multiple remotes.
#[async_trait]
pub trait AccountSync {
    /// Error type for account sync.
    type Error: std::error::Error + std::fmt::Debug;

    /// Perform a full sync of the account using
    /// the default options.
    ///
    /// If the account does not exist on the remote
    /// server the account will be created and
    /// [RemoteSync::sync_file_transfers] will be called
    /// to ensure the transfers queue is synced.
    async fn sync(&self) -> SyncResult<Self::Error>;

    /// Perform a full sync of the account
    /// using the given options.
    ///
    /// See the documentation for [RemoteSync::sync] for more details.
    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> SyncResult<Self::Error>;

    /// Sync file transfers.
    ///
    /// Updates the file transfers queue with any pending
    /// uploads or downloads by comparing the local file
    /// state with the file state on remote server(s).
    #[cfg(feature = "files")]
    async fn sync_file_transfers(
        &self,
        options: &SyncOptions,
    ) -> SyncResult<Self::Error>;

    /// Force update an account on remote servers.
    ///
    /// Should be called after making destructive
    /// changes to an account's folders. For example, if
    /// the encryption cipher has been changed, a folder
    /// password was changed or folder(s) were compacted.
    async fn force_update(
        &self,
        account_data: UpdateSet,
        options: &SyncOptions,
    ) -> SyncResult<Self::Error>;
}

/// Client that can synchronize with a remote data source.
#[async_trait]
pub trait SyncClient {
    /// Error type for sync client.
    type Error: std::error::Error + std::fmt::Debug;

    /// Origin of the remote server.
    fn origin(&self) -> &Origin;

    /// Check if an account already exists.
    async fn account_exists(
        &self,
        address: &Address,
    ) -> Result<bool, Self::Error>;

    /// Create a new account.
    async fn create_account(
        &self,
        address: &Address,
        account: CreateSet,
    ) -> Result<(), Self::Error>;

    /// Update an account.
    async fn update_account(
        &self,
        address: &Address,
        account: UpdateSet,
    ) -> Result<(), Self::Error>;

    /// Fetch an account from a remote server.
    async fn fetch_account(&self) -> Result<CreateSet, Self::Error>;

    /// Delete the account on the server.
    async fn delete_account(&self) -> Result<(), Self::Error>;

    /// Sync status on the server.
    async fn sync_status(&self) -> Result<SyncStatus, Self::Error>;

    /// Sync with a remote.
    async fn sync(
        &self,
        packet: SyncPacket,
    ) -> Result<SyncPacket, Self::Error>;

    /// Scan commits in an event log.
    async fn scan(
        &self,
        request: ScanRequest,
    ) -> Result<ScanResponse, Self::Error>;

    /// Fetch a collection of event records since a given commit hash.
    async fn diff(
        &self,
        request: DiffRequest,
    ) -> Result<DiffResponse, Self::Error>;

    /// Patch an event log.
    ///
    /// If the request contains a commit hash then the remote will
    /// attempt to rewind to the commit before applying the patch.
    async fn patch(
        &self,
        request: PatchRequest,
    ) -> Result<PatchResponse, Self::Error>;
}

#[cfg(feature = "files")]
mod file_sync {
    use crate::{
        transfer::{FileSet, FileTransfersSet},
        CancelReason, ProgressChannel,
    };
    use async_trait::async_trait;
    use http::StatusCode;
    use sos_sdk::storage::files::ExternalFile;
    use std::path::Path;
    use tokio::sync::watch;

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
pub use file_sync::FileSyncClient;
