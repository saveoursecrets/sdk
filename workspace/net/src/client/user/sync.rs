use super::UserStorage;
use std::any::Any;
use crate::client::{RemoteSync, Result};
use async_trait::async_trait;
use sos_sdk::events::WriteEvent;

#[async_trait]
impl RemoteSync for UserStorage {
    async fn sync(&mut self) -> Result<()> {
        let _ = self.sync_lock.lock().await;
        for remote in self.remotes.values_mut() {
            remote.sync().await?;
        }
        Ok(())
    }

    async fn sync_local_events(&self, events: &[WriteEvent]) -> Result<()> {
        let _ = self.sync_lock.lock().await;
        todo!();
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
