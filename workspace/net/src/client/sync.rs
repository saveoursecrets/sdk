use super::Error;
use async_trait::async_trait;
use sos_sdk::sync::Origin;

/// Error type that can be returned from a sync operation.
pub type SyncError = sos_sdk::sync::SyncError<Error>;

/// Options for sync operation.
#[derive(Default, Debug)]
pub struct SyncOptions {
    /// Only sync these origins.
    pub origins: Vec<Origin>,
}

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
    async fn patch_devices(&self) -> Option<SyncError>;
}
