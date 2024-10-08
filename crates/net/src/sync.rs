use crate::{
    protocol::{
        CreateSet, DiffRequest, DiffResponse, MergeOutcome, Origin,
        PatchRequest, PatchResponse, ScanRequest, ScanResponse, SyncOptions,
        SyncPacket, SyncStatus, UpdateSet,
    },
    CancelReason, Result,
};
use async_trait::async_trait;
use sos_sdk::storage;
use std::path::Path;

/// Result of a sync operation with a single remote.
#[derive(Debug)]
pub struct RemoteResult {
    /// Origin of the remote.
    pub origin: Origin,
    /// Result of the sync operation.
    pub result: Result<Option<MergeOutcome>>,
}

/// Result of a sync operation.
#[derive(Debug, Default)]
pub struct SyncResult {
    /// Result of syncing with remote servers.
    pub remotes: Vec<RemoteResult>,
}

impl SyncResult {
    /// Find the first sync error.
    pub fn first_error(self) -> Option<crate::Error> {
        self.remotes.into_iter().find_map(|res| {
            if res.result.is_err() {
                res.result.err()
            } else {
                None
            }
        })
    }

    /// Find the first sync error by reference.
    pub fn first_error_ref(&self) -> Option<&crate::Error> {
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
    /// Perform a full sync of the account using
    /// the default options.
    ///
    /// If the account does not exist on the remote
    /// server the account will be created and
    /// [RemoteSync::sync_file_transfers] will be called
    /// to ensure the transfers queue is synced.
    async fn sync(&self) -> RemoteResult;

    /// Perform a full sync of the account
    /// using the given options.
    ///
    /// See the documentation for [RemoteSync::sync] for more details.
    async fn sync_with_options(&self, options: &SyncOptions) -> RemoteResult;

    /// Sync file transfers.
    ///
    /// Updates the file transfers queue with any pending
    /// uploads or downloads by comparing the local file
    /// state with the file state on remote server(s).
    #[cfg(feature = "files")]
    async fn sync_file_transfers(&self) -> RemoteResult;

    /// Force update an account on remote servers.
    ///
    /// Should be called after making destructive
    /// changes to an account's folders. For example, if
    /// the encryption cipher has been changed, a folder
    /// password was changed or folder(s) were compacted.
    async fn force_update(&self, account_data: UpdateSet) -> RemoteResult;
}

/// Trait for types that can sync with multiple remotes.
#[async_trait]
pub trait AccountSync {
    /// Perform a full sync of the account using
    /// the default options.
    ///
    /// If the account does not exist on the remote
    /// server the account will be created and
    /// [RemoteSync::sync_file_transfers] will be called
    /// to ensure the transfers queue is synced.
    async fn sync(&self) -> SyncResult;

    /// Perform a full sync of the account
    /// using the given options.
    ///
    /// See the documentation for [RemoteSync::sync] for more details.
    async fn sync_with_options(&self, options: &SyncOptions) -> SyncResult;

    /// Sync file transfers.
    ///
    /// Updates the file transfers queue with any pending
    /// uploads or downloads by comparing the local file
    /// state with the file state on remote server(s).
    #[cfg(feature = "files")]
    async fn sync_file_transfers(&self, options: &SyncOptions) -> SyncResult;

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
    ) -> SyncResult;
}

/// Client that can synchronize with a remote server.
#[async_trait]
pub trait SyncClient {
    /// Origin of the remote server.
    fn origin(&self) -> &Origin;

    /// Check if an account already exists.
    async fn account_exists(&self) -> Result<bool>;

    /// Create a new account.
    async fn create_account(&self, account: CreateSet) -> Result<()>;

    /// Update an account.
    async fn update_account(&self, account: UpdateSet) -> Result<()>;

    /// Fetch an account from a remote server.
    async fn fetch_account(&self) -> Result<CreateSet>;

    /// Delete the account on the server.
    async fn delete_account(&self) -> Result<()>;

    /// Sync status on the server.
    async fn sync_status(&self) -> Result<SyncStatus>;

    /// Sync with a remote.
    async fn sync(&self, packet: SyncPacket) -> Result<SyncPacket>;

    /// Scan commits in an event log.
    async fn scan(&self, request: ScanRequest) -> Result<ScanResponse>;

    /// Fetch a collection of event records since a given commit hash.
    async fn diff(&self, request: DiffRequest) -> Result<DiffResponse>;

    /// Patch an event log.
    ///
    /// If the request contains a commit hash then the remote will
    /// attempt to rewind to the commit before applying the patch.
    async fn patch(&self, request: PatchRequest) -> Result<PatchResponse>;

    /// Send a file.
    #[cfg(feature = "files")]
    async fn upload_file(
        &self,
        file_info: &storage::files::ExternalFile,
        path: &Path,
        progress: crate::ProgressChannel,
        cancel: tokio::sync::watch::Receiver<CancelReason>,
    ) -> Result<http::StatusCode>;

    /// Receive a file.
    #[cfg(feature = "files")]
    async fn download_file(
        &self,
        file_info: &storage::files::ExternalFile,
        path: &Path,
        progress: crate::ProgressChannel,
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
        local_files: crate::protocol::FileSet,
    ) -> Result<crate::protocol::FileTransfersSet>;
}
