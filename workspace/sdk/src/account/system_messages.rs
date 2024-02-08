//! System messages are persistent user notifications.
//!
//! They can be used to surface information such as
//! a failed synchronization, due date for backup,
//! automated security report or other information about
//! an account.
//!
//! System messages use keys so that we don't write lots
//! of failed synchronization messages, instead the last
//! failure would overwrite the previous messages.
//!
//! To prevent overwriting previous messages use a unique
//! key such as a UUID.
use crate::{vfs, Paths, Result, Error};
use serde::{Deserialize, Serialize};
use std::{cmp::Ordering, collections::HashMap, path::PathBuf};
use time::OffsetDateTime;
use tokio::sync::broadcast;

/// Level for system messages.
#[derive(
    Debug, Default, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq,
)]
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
/// lower priority messages. If priorities are 
/// equal sorting uses the created date and time.
#[derive(Debug, Serialize, Deserialize, Ord, Eq, PartialEq)]
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

fn stream_channel() -> broadcast::Sender<usize> {
    let (stream, _) = broadcast::channel(8);
    stream
}

/// Persistent system message notifications.
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemMessages {
    #[serde(flatten)]
    messages: HashMap<String, SysMessage>,
    /// Path to the file on disc.
    #[serde(skip)]
    path: PathBuf,
    #[serde(skip, default = "stream_channel")]
    stream: broadcast::Sender<usize>,
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
            stream: stream_channel(),
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
    pub fn subscribe(&self) -> broadcast::Receiver<usize> {
        self.stream.subscribe()
    }

    /// Number of system messages.
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the system messages collection is empty.
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Create or overwrite a system message.
    ///
    /// Changes are written to disc.
    pub async fn insert(
        &mut self,
        key: String,
        message: SysMessage,
    ) -> Result<()> {
        self.messages.insert(key, message);
        self.save().await
    }

    /// Mark a message as read.
    ///
    /// Changes are written to disc.
    pub async fn mark_read(&mut self, key: impl AsRef<str>) -> Result<()> {
        let updated = if let Some(message) = self
            .messages
            .get_mut(key.as_ref()) {
            message.is_read = true;
            true
        } else { false };

        if updated {
            self.save().await
        } else {
            Err(Error::NoSysMessage(key.as_ref().to_owned()))
        }
    }
    
    /// Get a message.
    pub fn get(&self, key: impl AsRef<str>) -> Option<&SysMessage> {
        self.messages.get(key.as_ref())
    }

    /// Remove a system message.
    ///
    /// Changes are written to disc.
    pub async fn remove(&mut self, key: impl AsRef<str>) -> Result<()> {
        self.messages.remove(key.as_ref());
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
        let _ = self.stream.send(self.messages.len());
        Ok(())
    }
}
