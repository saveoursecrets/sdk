use super::Error;
use async_trait::async_trait;
use sos_sdk::sync::Origin;

/// Enumeration of error types that can be returned
/// from a sync operation.
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
    async fn sync(&self) -> Option<SyncError>;

    /// Perform a full sync of the account
    /// using the given options.
    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> Option<SyncError>;

    /// Patch the device log on the remote.
    async fn patch_devices(&self) -> Option<SyncError>;
}
