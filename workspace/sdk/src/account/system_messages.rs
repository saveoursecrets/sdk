//! System messages are persistent user notifications.
//!
//! They can be used to surface information such as
//! a failed synchronization, software update, due date for backup,
//! automated security report or other information about an account.
//!
//! System messages use keys so that we don't write lots
//! of failed synchronization messages, instead the last
//! failure would overwrite the previous messages. To avoid 
//! this behavior use a unique key such as a UUID.
//!
//! Use [SystemMessages::subscribe] to listen for
//! changes to the underlying collection. This allows 
//! an interface to show the number of unread system 
//! messages.
use crate::{vfs, Error, Paths, Result};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::HashMap, path::PathBuf};
use time::OffsetDateTime;
use tokio::sync::broadcast;
use serde_with::{serde_as, DisplayFromStr};
use urn::Urn;

/// Type sent to broadcast channel subscribers.
///
/// The total number of system messages and the number
/// of unread messages.
pub type SysMessageState = (usize, usize);

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
}

/// System message notification.
///
/// Higher priority messages are sorted before
/// lower priority messages, if priorities are
/// equal sorting uses the created date and time.
#[derive(Debug, Serialize, Deserialize, Ord, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SysMessage {
    /// Date and time the message was created.
    pub created: OffsetDateTime,
    /// Message priority.
    pub priority: usize,
    /// Title for the message.
    pub title: String,
    /// Content of the message.
    pub content: String,
    /// Indicates if the message has been read.
    pub is_read: bool,
    /// Level indicator.
    pub level: SysMessageLevel,
}

impl SysMessage {
    /// Create a new message.
    pub fn new(title: String, content: String) -> Self {
        Self {
            created: OffsetDateTime::now_utc(),
            priority: 0,
            title,
            content,
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
            created: OffsetDateTime::now_utc(),
            priority,
            title,
            content,
            is_read: false,
            level,
        }
    }
}

impl PartialOrd for SysMessage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match other.priority.cmp(&self.priority) {
            std::cmp::Ordering::Equal => {
                Some(other.created.cmp(&self.created))
            }
            result => Some(result),
        }
    }
}

fn stream_channel() -> broadcast::Sender<SysMessageState> {
    let (stream, _) = broadcast::channel(8);
    stream
}

/// Persistent system message notifications.
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemMessages {
    #[serde_as(as = "HashMap<DisplayFromStr, _>")]
    #[serde(flatten)]
    messages: HashMap<Urn, SysMessage>,
    /// Path to the file on disc.
    #[serde(skip)]
    path: PathBuf,
    /// Broadcast channel.
    #[serde(skip, default = "stream_channel")]
    channel: broadcast::Sender<SysMessageState>,
}

impl SystemMessages {
    /// Create new system messages using the given paths.
    ///
    /// # Panics
    ///
    /// If the given paths are global.
    ///
    pub fn new(paths: &Paths) -> Self {
        Self {
            path: paths.system_messages(),
            messages: Default::default(),
            channel: stream_channel(),
        }
    }

    /// Load the system messages stored on disc into memory.
    pub async fn load(&mut self) -> Result<()> {
        let content = vfs::read(&self.path).await?;
        let sys: SystemMessages = serde_json::from_slice(&content)?;
        self.messages = sys.messages;
        Ok(())
    }

    /// Subscribe to the broadcast channel.
    pub fn subscribe(&self) -> broadcast::Receiver<SysMessageState> {
        self.channel.subscribe()
    }

    /// Number of system messages.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the system messages collection is empty.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Number of unread system messages.
    pub fn unread_len(&self) -> usize {
        self.messages.values().fold(0, |acc, item| {
            if !item.is_read {
                acc + 1
            } else {
                acc
            }
        })
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
        self.messages.insert(key, message);
        self.save().await
    }

    /// Mark a message as read.
    ///
    /// Changes are written to disc.
    pub async fn mark_read(&mut self, key: &Urn) -> Result<()> {
        let updated =
            if let Some(message) = self.messages.get_mut(key) {
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
        self.messages.get(key)
    }

    /// Remove a system message.
    ///
    /// Changes are written to disc.
    pub async fn remove(&mut self, key: &Urn) -> Result<()> {
        self.messages.remove(key);
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
    pub fn sorted_list(&self) -> Vec<&SysMessage> {
        let mut messages: Vec<_> = self.messages.values().collect();
        messages.sort();
        messages
    }

    /// Save system messages to disc.
    async fn save(&self) -> Result<()> {
        let buf = serde_json::to_vec_pretty(self)?;
        vfs::write(&self.path, buf).await?;
        let _ = self.channel.send((self.messages.len(), self.unread_len()));
        Ok(())
    }
}
