use super::{Error, Origin, Result};
use async_trait::async_trait;
use sos_sdk::{
    commit::{CommitHash, CommitProof},
    crypto::SecureAccessKey,
    events::Event,
    vault::Summary,
};
use std::any::Any;

/// Additional sync data.
pub enum SyncData {
    /// Secure access key needs to be sent
    /// along with the create vault event.
    CreateVault(SecureAccessKey),
}

/// Enumeration of error types that can be returned
/// from a sync operation.
pub enum SyncError {
    /// Single remote error.
    One(Error),
    /// Collection of errors by remote origin.
    Multiple(Vec<(Origin, Error)>),
}

/// Options for sync operation.
#[derive(Default, Debug)]
pub struct SyncOptions {
    /// Only sync these origins.
    pub origins: Vec<Origin>,
}

/// Trait for types that can sync accounts with a remote.
#[async_trait]
pub trait RemoteSync: Sync + Send + Any {
    /// Perform a full sync of the account using
    /// the default options.
    async fn sync(&self) -> Option<SyncError>;

    /// Perform a full sync of the account
    /// using the given options.
    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> Option<SyncError>;

    /// Must be called before applying changes to a local
    /// provider.
    ///
    /// If the local is behind the remote and can safely pull
    /// this allows us to apply remote changes before committing
    /// changes to the local provider.
    ///
    /// Returns a boolean indicating if changes were made so that
    /// callers can re-compute their proofs.
    async fn sync_before_apply_change(
        &self,
        folder: &Summary,
        last_commit: &CommitHash,
        commit_proof: &CommitProof,
    ) -> Result<bool>;

    /// Send events after changes to the local storage
    /// to a remote.
    ///
    /// The last commit hash and proof must be acquired
    /// before applying changes to the local storage.
    async fn sync_send_events(
        &self,
        folder: &Summary,
        last_commit: &CommitHash,
        commit_proof: &CommitProof,
        events: &[Event],
        data: &[SyncData],
    ) -> std::result::Result<(), SyncError>;

    /// Cast to the Any trait.
    fn as_any(&self) -> &(dyn Any + Send + Sync);

    /// Cast to the Any trait.
    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync);
}
