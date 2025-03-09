use crate::{BackendTarget, Error};
use async_trait::async_trait;
use sos_core::AccountId;
use sos_database::SystemMessagesProvider as DbSystemMessages;
use sos_filesystem::SystemMessagesProvider as FsSystemMessages;
use sos_system_messages::{
    SysMessage, SysMessageCount, SystemMessageManager, SystemMessageMap,
    SystemMessageStorage, SystemMessages as SystemMessagesImpl,
};
use tokio::sync::broadcast;
use urn::Urn;

/// Collection of system messages for an account.
pub struct SystemMessages(SystemMessagesImpl<Error>);

impl SystemMessages {
    /// Create new system messages.
    pub fn new(target: BackendTarget, account_id: &AccountId) -> Self {
        match target {
            BackendTarget::FileSystem(paths) => {
                Self(SystemMessagesImpl::<Error>::new(Box::new(
                    FsSystemMessages::new(paths.clone()),
                )))
            }
            BackendTarget::Database(_, client) => {
                Self(SystemMessagesImpl::<Error>::new(Box::new(
                    DbSystemMessages::new(*account_id, client),
                )))
            }
        }
    }
}

#[async_trait]
impl SystemMessageManager for SystemMessages {
    type Error = Error;

    async fn load_system_messages(&mut self) -> Result<(), Self::Error> {
        self.0.load_system_messages().await
    }

    fn subscribe(&self) -> broadcast::Receiver<SysMessageCount> {
        self.0.subscribe()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn counts(&self) -> SysMessageCount {
        self.0.counts()
    }

    fn iter(&self) -> impl Iterator<Item = (&Urn, &SysMessage)> {
        self.0.iter()
    }

    fn get(&self, key: &Urn) -> Option<&SysMessage> {
        self.0.get(key)
    }

    fn sorted_list(&self) -> Vec<(&Urn, &SysMessage)> {
        self.0.sorted_list()
    }
}

#[async_trait]
impl SystemMessageStorage for SystemMessages {
    type Error = Error;

    async fn list_system_messages(
        &self,
    ) -> Result<SystemMessageMap, Self::Error> {
        self.0.list_system_messages().await
    }

    async fn insert_system_message(
        &mut self,
        key: Urn,
        message: SysMessage,
    ) -> Result<(), Self::Error> {
        self.0.insert_system_message(key, message).await
    }

    async fn remove_system_message(
        &mut self,
        key: &Urn,
    ) -> Result<(), Self::Error> {
        self.0.remove_system_message(key).await
    }

    async fn mark_system_message(
        &mut self,
        key: &Urn,
        is_read: bool,
    ) -> Result<(), Self::Error> {
        self.0.mark_system_message(key, is_read).await
    }

    async fn clear_system_messages(&mut self) -> Result<(), Self::Error> {
        self.0.clear_system_messages().await
    }
}
