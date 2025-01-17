//! System messages provider for the file system.
use crate::{write_exclusive, Error};
use async_fd_lock::LockRead;
use async_trait::async_trait;
use sos_core::Paths;
use sos_system_messages::{
    SysMessage, SystemMessageMap, SystemMessageStorage,
};
use sos_vfs::{self as vfs, File};
use std::{path::PathBuf, sync::Arc};
use tokio::io::AsyncReadExt;
use urn::Urn;

/// File system storage provider for system messages.
pub struct SystemMessagesProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_system_messages::Error>
        + From<Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    path: PathBuf,
    marker: std::marker::PhantomData<E>,
}

impl<E> SystemMessagesProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_system_messages::Error>
        + From<Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    /// Create a system messages provider.
    pub fn new(paths: Arc<Paths>) -> Self {
        Self {
            path: paths.system_messages_file(),
            marker: std::marker::PhantomData,
        }
    }

    /// Save system messages to disc.
    async fn save(&self, messages: &SystemMessageMap) -> Result<(), E> {
        let buf = serde_json::to_vec_pretty(messages).map_err(Error::from)?;
        write_exclusive(&self.path, buf).await?;
        Ok(())
    }
}

#[async_trait]
impl<E> SystemMessageStorage for SystemMessagesProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_system_messages::Error>
        + From<Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    type Error = E;

    async fn list_system_messages(
        &self,
    ) -> Result<SystemMessageMap, Self::Error> {
        if vfs::try_exists(&self.path).await? {
            let file = File::open(&self.path).await?;
            let mut guard = file.lock_read().await.map_err(|e| e.error)?;
            let mut content = Vec::new();
            guard.read_to_end(&mut content).await?;

            Ok(serde_json::from_slice::<SystemMessageMap>(&content)
                .map_err(Error::from)?)
        } else {
            Ok(Default::default())
        }
    }

    async fn insert_system_message(
        &mut self,
        key: Urn,
        message: SysMessage,
    ) -> Result<(), Self::Error> {
        let mut messages = self.list_system_messages().await?;
        messages.0.insert(key, message);
        self.save(&messages).await?;
        Ok(())
    }

    async fn remove_system_message(
        &mut self,
        key: &Urn,
    ) -> Result<(), Self::Error> {
        let mut messages = self.list_system_messages().await?;
        messages.0.remove(key);
        self.save(&messages).await?;
        Ok(())
    }

    async fn mark_system_message(
        &mut self,
        key: &Urn,
        is_read: bool,
    ) -> Result<(), Self::Error> {
        let mut messages = self.list_system_messages().await?;
        if let Some(msg) = messages.0.get_mut(key) {
            msg.is_read = is_read;
            self.save(&messages).await?;
        }
        Ok(())
    }

    async fn clear_system_messages(&mut self) -> Result<(), Self::Error> {
        self.save(&Default::default()).await
    }
}
