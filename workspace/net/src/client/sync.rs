use super::Result;
use async_trait::async_trait;
use sos_sdk::{commit::{CommitHash, CommitProof}, events::WriteEvent, vault::Summary};
use std::any::Any;

/// Trait for types that can sync accounts with a remote.
#[async_trait]
pub trait RemoteSync: Sync + Send + Any {
    /// Perform a full sync of the account.
    async fn sync(&mut self) -> Result<()>;

    /// Send events from changes to the local storage
    /// to a remote.
    ///
    /// The last commit hash and proof must be acquired 
    /// before applying changes to the local storage.
    async fn sync_send_events(
        &mut self,
        last_commit: Option<CommitHash>,
        client_proof: CommitProof,
        folder: &Summary,
        events: &[WriteEvent<'static>],
    ) -> Result<()>;

    /// Receive events from changes to remote storage.
    async fn sync_receive_events(
        &mut self,
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
