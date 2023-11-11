use super::UserStorage;
use crate::client::{RemoteSync, Result};
use async_trait::async_trait;
use sos_sdk::events::WriteEvent;

#[async_trait]
impl RemoteSync for UserStorage {
    async fn sync(&mut self) -> Result<()> {
        let _ = self.sync_lock.lock().await;
        todo!();
    }

    async fn sync_local_events(&self, events: &[WriteEvent]) -> Result<()> {
        let _ = self.sync_lock.lock().await;
        todo!();
    }
}
