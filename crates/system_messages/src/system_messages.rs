use crate::Error;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{cmp::Ordering, collections::HashMap};
use time::OffsetDateTime;
use tokio::sync::broadcast;
use urn::Urn;

/// Boxed storage provider.
pub type SystemMessageStorageProvider<E> =
    Box<dyn SystemMessageStorage<Error = E> + Send + Sync + 'static>;

/// Manages system messages.
#[async_trait]
pub trait SystemMessageManager {
    /// Error type.
    type Error: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + Send
        + Sync
        + 'static;

    /// Load system messages for an account into memory.
    async fn load_system_messages(&mut self) -> Result<(), Self::Error>;

    /// Subscribe to the broadcast channel.
    fn subscribe(&self) -> broadcast::Receiver<SysMessageCount>;

    /// Number of system messages.
    fn len(&self) -> usize;

    /// Whether the system messages collection is empty.
    fn is_empty(&self) -> bool;

    /// Message counts.
    fn counts(&self) -> SysMessageCount;

    /// Iterator of the system messages.
    fn iter(&self) -> impl Iterator<Item = (&Urn, &SysMessage)>;

    /// Get a message.
    fn get(&self, key: &Urn) -> Option<&SysMessage>;

    /// Sorted list of system messages.
    fn sorted_list(&self) -> Vec<(&Urn, &SysMessage)>;
}

/// Storage for system messages.
#[async_trait]
pub trait SystemMessageStorage {
    /// Error type.
    type Error: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + Send
        + Sync
        + 'static;

    /// List system messages for an account.
    async fn list_system_messages(
        &self,
    ) -> Result<SystemMessageMap, Self::Error>;

    /// Add a system message to an account.
    async fn insert_system_message(
        &mut self,
        key: Urn,
        message: SysMessage,
    ) -> Result<(), Self::Error>;

    /// Remove a system message from an account.
    async fn remove_system_message(
        &mut self,
        key: &Urn,
    ) -> Result<(), Self::Error>;

    /// Mark a system message as read or unread.
    async fn mark_system_message(
        &mut self,
        key: &Urn,
        is_read: bool,
    ) -> Result<(), Self::Error>;

    /// Delete all system messages for an account.
    async fn clear_system_messages(&mut self) -> Result<(), Self::Error>;
}

/// System messages count.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct SysMessageCount {
    /// Total number of messages.
    pub total: usize,
    /// Number of unread messages.
    pub unread: usize,
    /// Number of unread info messages.
    pub unread_info: usize,
    /// Number of unread warn messages.
    pub unread_warn: usize,
    /// Number of unread error messages.
    pub unread_error: usize,
}

/// Level for system messages.
#[derive(
    Debug,
    Default,
    Clone,
    Serialize,
    Deserialize,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
)]
#[serde(rename_all = "lowercase")]
pub enum SysMessageLevel {
    /// Informational message.
    #[default]
    Info,
    /// Warning message.
    Warn,
    /// Error message.
    Error,
    /// Progress message such as an upload or download.
    Progress,
    /// Completed operation (eg: upload or download).
    Done,
}

/// System message notification.
///
/// Higher priority messages are sorted before
/// lower priority messages, if priorities are
/// equal sorting uses the created date and time.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SysMessage {
    /// Optional identifier for the message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    /// Date and time the message was created.
    pub created: OffsetDateTime,
    /// Message priority.
    pub priority: usize,
    /// Title for the message.
    pub title: String,
    /// Sub title byline for the message.
    pub sub_title: Option<String>,
    /// Content of the message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// Indicates if the message has been read.
    pub is_read: bool,
    /// Level indicator.
    pub level: SysMessageLevel,
}
impl SysMessage {
    /// Create a new message.
    pub fn new(title: String, content: String) -> Self {
        Self {
            id: None,
            created: OffsetDateTime::now_utc(),
            priority: 0,
            title,
            sub_title: None,
            content: Some(content),
            is_read: false,
            level: Default::default(),
        }
    }

    /// Create a new message with the given priority and level.
    pub fn new_priority(
        title: String,
        content: String,
        priority: usize,
        level: SysMessageLevel,
    ) -> Self {
        Self {
            id: None,
            created: OffsetDateTime::now_utc(),
            priority,
            title,
            sub_title: None,
            content: Some(content),
            is_read: false,
            level,
        }
    }
}

impl PartialOrd for SysMessage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SysMessage {
    fn cmp(&self, other: &Self) -> Ordering {
        match other.priority.cmp(&self.priority) {
            std::cmp::Ordering::Equal => other.created.cmp(&self.created),
            result => result,
        }
    }
}

/// Collection of system messages.
#[serde_as]
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct SystemMessageMap(
    #[serde_as(as = "HashMap<DisplayFromStr, _>")]
    pub  HashMap<Urn, SysMessage>,
);

impl From<HashMap<Urn, SysMessage>> for SystemMessageMap {
    fn from(value: HashMap<Urn, SysMessage>) -> Self {
        Self(value)
    }
}

impl SystemMessageMap {
    /// Borrowed iterator.
    pub fn iter(
        &self,
    ) -> std::collections::hash_map::Iter<'_, Urn, SysMessage> {
        self.0.iter()
    }

    /// Owned iterator.
    pub fn into_iter(
        self,
    ) -> std::collections::hash_map::IntoIter<Urn, SysMessage> {
        self.0.into_iter()
    }
}

/// Persistent system message notifications.
pub struct SystemMessages<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + Send
        + Sync
        + 'static,
{
    provider: SystemMessageStorageProvider<E>,
    messages: SystemMessageMap,
    channel: broadcast::Sender<SysMessageCount>,
}

impl<E> SystemMessages<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + Send
        + Sync
        + 'static,
{
    /// Create new system messages.
    pub fn new(provider: SystemMessageStorageProvider<E>) -> Self {
        let (channel, _) = broadcast::channel(8);
        Self {
            provider,
            messages: Default::default(),
            channel,
        }
    }

    fn send_counts(&self) {
        if let Err(e) = self.channel.send(self.counts()) {
            tracing::error!(error = %e, "system_messages::send");
        }
    }
}

#[async_trait]
impl<E> SystemMessageManager for SystemMessages<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + Send
        + Sync
        + 'static,
{
    type Error = E;

    async fn load_system_messages(&mut self) -> Result<(), E> {
        self.messages = self.provider.list_system_messages().await?;
        Ok(())
    }

    fn subscribe(&self) -> broadcast::Receiver<SysMessageCount> {
        self.channel.subscribe()
    }

    fn len(&self) -> usize {
        self.messages.0.len()
    }

    fn is_empty(&self) -> bool {
        self.messages.0.is_empty()
    }

    fn counts(&self) -> SysMessageCount {
        let mut counts = SysMessageCount { total: self.messages.0.len(), ..Default::default() };
        for item in self.messages.0.values() {
            if !item.is_read {
                counts.unread += 1;
                if matches!(item.level, SysMessageLevel::Info) {
                    counts.unread_info += 1;
                }
                if matches!(item.level, SysMessageLevel::Warn) {
                    counts.unread_warn += 1;
                }
                if matches!(item.level, SysMessageLevel::Error) {
                    counts.unread_error += 1;
                }
            }
        }
        counts
    }

    fn iter(&self) -> impl Iterator<Item = (&Urn, &SysMessage)> {
        self.messages.iter()
    }

    fn get(&self, key: &Urn) -> Option<&SysMessage> {
        self.messages.0.get(key)
    }

    fn sorted_list(&self) -> Vec<(&Urn, &SysMessage)> {
        let mut messages: Vec<_> = self.messages.iter().collect();
        messages.sort_by(|a, b| a.1.cmp(b.1));
        messages
    }
}

#[async_trait]
impl<E> SystemMessageStorage for SystemMessages<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<Error>
        + Send
        + Sync
        + 'static,
{
    type Error = E;

    async fn list_system_messages(
        &self,
    ) -> Result<SystemMessageMap, Self::Error> {
        self.provider.list_system_messages().await
    }

    async fn insert_system_message(
        &mut self,
        key: Urn,
        message: SysMessage,
    ) -> Result<(), Self::Error> {
        self.messages.0.insert(key.clone(), message.clone());
        self.provider.insert_system_message(key, message).await?;
        self.send_counts();
        Ok(())
    }

    async fn remove_system_message(
        &mut self,
        key: &Urn,
    ) -> Result<(), Self::Error> {
        self.messages.0.remove(key);
        self.provider.remove_system_message(key).await?;
        self.send_counts();
        Ok(())
    }

    async fn mark_system_message(
        &mut self,
        key: &Urn,
        is_read: bool,
    ) -> Result<(), Self::Error> {
        if let Some(message) = self.messages.0.get_mut(key) {
            message.is_read = true;
            self.provider.mark_system_message(key, is_read).await?;
            self.send_counts();
            Ok(())
        } else {
            Err(Error::NoSysMessage(key.to_string()).into())
        }
    }

    async fn clear_system_messages(&mut self) -> Result<(), Self::Error> {
        self.messages = Default::default();
        self.provider.clear_system_messages().await?;
        self.send_counts();
        Ok(())
    }
}
