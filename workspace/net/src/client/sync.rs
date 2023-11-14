use super::Result;
use async_trait::async_trait;
use sos_sdk::{commit::CommitHash, events::WriteEvent, vault::Summary};
use std::any::Any;

/// Trait for types that can sync accounts with a remote.
#[async_trait]
pub trait RemoteSync: Sync + Send + Any {
    /// Perform a full sync of the account.
    async fn sync(&mut self) -> Result<()>;

    /// Send events from changes to the local storage
    /// to a remote.
    async fn sync_send_events(
        &mut self,
        commit: Option<CommitHash>,
        folder: &Summary,
        events: &[WriteEvent<'static>],
    ) -> Result<()>;

    /// Receive events from changes to remote storage.
    async fn sync_receive_events(
        &mut self,
        events: &[WriteEvent<'static>],
    ) -> Result<()>;

    /// Cast to the Any trait.
    fn as_any(&self) -> &dyn Any;

    /// Cast to the Any trait.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}
