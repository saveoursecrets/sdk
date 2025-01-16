//! System messages provider for the file system.
use crate::Error;
use async_trait::async_trait;
use sos_core::{AccountId, Paths};
use sos_system_messages::{
    SysMessage, SystemMessageMap, SystemMessageStorage,
};
use sos_vfs as vfs;
use std::{path::PathBuf, sync::Arc};
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
        vfs::write_exclusive(&self.path, buf).await?;
        Ok(())
    }
}

#[async_trait()]
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
        _account_id: &AccountId,
    ) -> Result<SystemMessageMap, Self::Error> {
        if vfs::try_exists(&self.path).await? {
            let content = vfs::read_exclusive(&self.path).await?;
            Ok(serde_json::from_slice::<SystemMessageMap>(&content)
                .map_err(Error::from)?)
        } else {
            Ok(Default::default())
        }
    }

    async fn insert_system_message(
        &self,
        account_id: &AccountId,
        key: Urn,
        message: SysMessage,
    ) -> Result<(), Self::Error> {
        let mut messages = self.list_system_messages(account_id).await?;
        messages.0.insert(key, message);
        self.save(&messages).await?;
        Ok(())
    }

    async fn remove_system_message(
        &self,
        account_id: &AccountId,
        key: &Urn,
    ) -> Result<(), Self::Error> {
        let mut messages = self.list_system_messages(account_id).await?;
        messages.0.remove(key);
        self.save(&messages).await?;
        Ok(())
    }

    async fn mark_system_message(
        &self,
        account_id: &AccountId,
        key: &Urn,
        is_read: bool,
    ) -> Result<(), Self::Error> {
        let mut messages = self.list_system_messages(account_id).await?;
        if let Some(msg) = messages.0.get_mut(key) {
            msg.is_read = is_read;
            self.save(&messages).await?;
        }
        Ok(())
    }

    async fn clear_system_messages(
        &self,
        _account_id: &AccountId,
    ) -> Result<(), Self::Error> {
        self.save(&Default::default()).await
    }
}
