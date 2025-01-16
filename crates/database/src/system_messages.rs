//! System messages provider for a database table.
use std::collections::HashMap;

use crate::{
    db::{AccountEntity, SystemMessageEntity},
    Error,
};
use async_sqlite::Client;
use async_trait::async_trait;
use sos_core::AccountId;
use sos_system_messages::{
    SysMessage, SystemMessageMap, SystemMessageStorage,
};
use urn::Urn;

/// Database storage provider for system messages.
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
    account_id: AccountId,
    client: Client,
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
    pub fn new(account_id: AccountId, client: Client) -> Self {
        Self {
            account_id,
            client,
            marker: std::marker::PhantomData,
        }
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
        let account_id = self.account_id.clone();
        let rows = self
            .client
            .conn_and_then(move |conn| {
                let account = AccountEntity::new(&conn);
                let account_row = account.find_one(&account_id)?;
                let messages = SystemMessageEntity::new(&conn);
                Ok::<_, Error>(
                    messages.load_system_messages(account_row.row_id)?,
                )
            })
            .await
            .map_err(Error::from)?;

        let mut messages = HashMap::new();
        for row in rows {
            let (key, message) = row.try_into()?;
            messages.insert(key, message);
        }

        Ok(messages.into())
    }

    async fn insert_system_message(
        &mut self,
        key: Urn,
        message: SysMessage,
    ) -> Result<(), Self::Error> {
        let account_id = self.account_id.clone();
        let key = key.to_string();
        let message = serde_json::to_string(&message).map_err(Error::from)?;
        Ok(self
            .client
            .conn(move |conn| {
                let account = AccountEntity::new(&conn);
                let account_row = account.find_one(&account_id)?;
                let messages = SystemMessageEntity::new(&conn);
                Ok(messages.insert_system_message(
                    account_row.row_id,
                    &key,
                    &message,
                )?)
            })
            .await
            .map_err(Error::from)?)
    }

    async fn remove_system_message(
        &mut self,
        key: &Urn,
    ) -> Result<(), Self::Error> {
        let account_id = self.account_id.clone();
        let key = key.to_string();
        Ok(self
            .client
            .conn(move |conn| {
                let account = AccountEntity::new(&conn);
                let account_row = account.find_one(&account_id)?;
                let messages = SystemMessageEntity::new(&conn);
                Ok(messages
                    .delete_system_message(account_row.row_id, &key)?)
            })
            .await
            .map_err(Error::from)?)
    }

    async fn mark_system_message(
        &mut self,
        key: &Urn,
        is_read: bool,
    ) -> Result<(), Self::Error> {
        let account_id = self.account_id.clone();
        let key = key.to_string();
        Ok(self
            .client
            .conn(move |conn| {
                let account = AccountEntity::new(&conn);
                let account_row = account.find_one(&account_id)?;
                let messages = SystemMessageEntity::new(&conn);
                Ok(messages.mark_system_message(
                    account_row.row_id,
                    &key,
                    is_read,
                )?)
            })
            .await
            .map_err(Error::from)?)
    }

    async fn clear_system_messages(&mut self) -> Result<(), Self::Error> {
        let account_id = self.account_id.clone();
        Ok(self
            .client
            .conn(move |conn| {
                let account = AccountEntity::new(&conn);
                let account_row = account.find_one(&account_id)?;
                let messages = SystemMessageEntity::new(&conn);
                Ok(messages.delete_system_messages(account_row.row_id)?)
            })
            .await
            .map_err(Error::from)?)
    }
}
