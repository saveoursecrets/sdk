//! System messages provider for a database table.
use crate::Error;
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
    pub fn new(client: Client) -> Self {
        Self {
            client,
            marker: std::marker::PhantomData,
        }
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
        todo!();
    }

    async fn insert_system_message(
        &self,
        account_id: &AccountId,
        key: Urn,
        message: SysMessage,
    ) -> Result<(), Self::Error> {
        todo!();
    }

    async fn remove_system_message(
        &self,
        account_id: &AccountId,
        key: &Urn,
    ) -> Result<(), Self::Error> {
        todo!();
    }

    async fn mark_system_message(
        &self,
        account_id: &AccountId,
        key: &Urn,
        is_read: bool,
    ) -> Result<(), Self::Error> {
        todo!();
    }

    async fn clear_system_messages(
        &self,
        _account_id: &AccountId,
    ) -> Result<(), Self::Error> {
        todo!();
    }
}
