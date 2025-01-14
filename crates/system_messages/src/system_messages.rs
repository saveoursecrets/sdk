use crate::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use sos_core::AccountId;
use std::{cmp::Ordering, collections::HashMap};
use time::OffsetDateTime;
use tokio::sync::broadcast;
use urn::Urn;

/// Boxed storage provider.
pub type SystemMessageStorageProvider<E> =
    Box<dyn SystemMessageStorage<Error = E> + Send + Sync + 'static>;

/// Storage for system messages.
#[async_trait]
pub trait SystemMessageStorage {
    /// Error type.
    type Error: std::error::Error + std::fmt::Debug;

    /// List system messages for an account.
    async fn list_system_messages(
        &self,
        account_id: &AccountId,
    ) -> std::result::Result<SystemMessageMap, Self::Error>;

    /// Add a system message to an account.
    async fn insert_system_message(
        &self,
        account_id: &AccountId,
        key: Urn,
        message: SysMessage,
    ) -> std::result::Result<(), Self::Error>;

    /// Remove a system message from an account.
    async fn remove_system_message(
        &self,
        account_id: &AccountId,
        key: &Urn,
    ) -> std::result::Result<(), Self::Error>;

    /// Mark a system message as read or unread.
    async fn mark_system_message(
        &self,
        account_id: &AccountId,
        key: &Urn,
        flag: bool,
    ) -> std::result::Result<(), Self::Error>;

    /// Delete all system messages for an account.
    async fn clear_system_messages(
        &self,
        account_id: &AccountId,
    ) -> std::result::Result<(), Self::Error>;
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
    Debug, Default, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq,
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
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
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

fn stream_channel() -> broadcast::Sender<SysMessageCount> {
    let (stream, _) = broadcast::channel(8);
    stream
}

/// Collection of system messages.
#[serde_as]
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct SystemMessageMap(
    #[serde_as(as = "HashMap<DisplayFromStr, _>")] HashMap<Urn, SysMessage>,
);

impl SystemMessageMap {
    /// Map iterator.
    pub fn iter(
        &self,
    ) -> std::collections::hash_map::Iter<'_, Urn, SysMessage> {
        self.0.iter()
    }
}

/// Persistent system message notifications.
#[derive(Debug)]
pub struct SystemMessages {
    messages: SystemMessageMap,
    /// Broadcast channel.
    channel: broadcast::Sender<SysMessageCount>,
}

impl SystemMessages {
    /// Create new system messages.
    pub fn new() -> Self {
        Self {
            messages: Default::default(),
            channel: stream_channel(),
        }
    }

    /// Load the system messages stored on disc into memory.
    ///
    /// If the file does not exist this is a noop.
    pub async fn load(&mut self) -> Result<()> {
        /*
        if vfs::try_exists(&self.path).await? {
            let content = vfs::read_exclusive(&self.path).await?;
            let sys: SystemMessages = serde_json::from_slice(&content)?;
            self.messages = sys.messages;
        }
        Ok(())
        */
        todo!();
    }

    /// Subscribe to the broadcast channel.
    pub fn subscribe(&self) -> broadcast::Receiver<SysMessageCount> {
        self.channel.subscribe()
    }

    /// Number of system messages.
    pub fn len(&self) -> usize {
        self.messages.0.len()
    }

    /// Whether the system messages collection is empty.
    pub fn is_empty(&self) -> bool {
        self.messages.0.is_empty()
    }

    /// Message counts.
    pub fn counts(&self) -> SysMessageCount {
        let mut counts: SysMessageCount = Default::default();
        counts.total = self.messages.0.len();
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

    /// Iterator of the system messages.
    pub fn iter(&self) -> impl Iterator<Item = (&Urn, &SysMessage)> {
        self.messages.iter()
    }

    /// Create or overwrite a system message.
    ///
    /// Changes are written to disc.
    pub async fn insert(
        &mut self,
        key: Urn,
        message: SysMessage,
    ) -> Result<()> {
        self.messages.0.insert(key, message);
        self.save().await
    }

    /// Mark a message as read.
    ///
    /// Changes are written to disc.
    pub async fn mark_read(&mut self, key: &Urn) -> Result<()> {
        let updated = if let Some(message) = self.messages.0.get_mut(key) {
            message.is_read = true;
            true
        } else {
            false
        };

        if updated {
            self.save().await
        } else {
            Err(Error::NoSysMessage(key.to_string()))
        }
    }

    /// Get a message.
    pub fn get(&self, key: &Urn) -> Option<&SysMessage> {
        self.messages.0.get(key)
    }

    /// Remove a system message.
    ///
    /// Changes are written to disc.
    pub async fn remove(&mut self, key: &Urn) -> Result<()> {
        self.messages.0.remove(key);
        self.save().await
    }

    /// Clear all system messages.
    ///
    /// Changes are written to disc.
    pub async fn clear(&mut self) -> Result<()> {
        self.messages = Default::default();
        self.save().await
    }

    /// Sorted list of system messages.
    pub fn sorted_list(&self) -> Vec<(&Urn, &SysMessage)> {
        let mut messages: Vec<_> = self.messages.iter().collect();
        messages.sort_by(|a, b| a.1.cmp(b.1));
        messages
    }

    /// Save system messages to disc.
    async fn save(&self) -> Result<()> {
        /*
        let buf = serde_json::to_vec_pretty(self)?;
        vfs::write_exclusive(&self.path, buf).await?;
        let _ = self.channel.send(self.counts());
        Ok(())
        */
        todo!();
    }
}
