use super::{Error, Result, Origin};
use async_trait::async_trait;
use sos_sdk::{
    commit::{CommitHash, CommitProof},
    events::WriteEvent,
    vault::Summary,
};
use std::any::Any;

/// Enumeration of error types that can be returned 
/// from a sync operation.
pub enum SyncError {
    /// Single remote error.
    One(Error),
    /// Collection of errors by remote origin.
    Multiple(Vec<(Origin, Error)>),
}

/// Trait for types that can sync accounts with a remote.
#[async_trait]
pub trait RemoteSync: Sync + Send + Any {
    /// Perform a full sync of the account.
    async fn sync(&self) -> Result<()>;

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
        last_commit: Option<&CommitHash>,
        client_proof: &CommitProof,
        folder: &Summary,
    ) -> Result<bool>;

    /// Send events after changes to the local storage
    /// to a remote.
    ///
    /// The last commit hash and proof must be acquired
    /// before applying changes to the local storage.
    async fn sync_send_events(
        &self,
        before_last_commit: Option<&CommitHash>,
        before_client_proof: &CommitProof,
        folder: &Summary,
        events: &[WriteEvent<'static>],
    ) -> std::result::Result<(), SyncError>;

    /// Receive events from changes to remote storage.
    async fn sync_receive_events(
        &self,
        events: &[WriteEvent<'static>],
    ) -> Result<()>;

    /*
    /// Respond to a change notification.
    ///
    /// The return flag indicates whether the change was made
    /// by this node which is determined by comparing the session
    /// identifier on the change notification with the current
    /// session identifier for this node.
    async fn handle_change(
        &mut self,
        change: ChangeNotification,
    ) -> Result<(bool, HashSet<ChangeAction>)>;
    */

    /// Cast to the Any trait.
    fn as_any(&self) -> &dyn Any;

    /// Cast to the Any trait.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}
