use super::Result;
use std::any::Any;
use async_trait::async_trait;
use sos_sdk::events::WriteEvent;

/// Trait for types that can sync accounts with a remote.
#[async_trait]
pub trait RemoteSync: Sync + Send + Any {
    /// Perform a full sync of the account.
    async fn sync(&mut self) -> Result<()>;

    /// Send events from changes to the local storage
    /// to a remote.
    async fn sync_local_events(&self, events: &[WriteEvent]) -> Result<()>;
    
    /// Cast to the Any trait.
    fn as_any(&self) -> &dyn Any;

    /// Cast to the Any trait.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}
