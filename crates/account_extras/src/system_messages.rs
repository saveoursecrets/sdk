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
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use sos_sdk::{
    constants::JSON_EXT, time::OffsetDateTime, urn::Urn, vfs, Paths,
};
use std::{cmp::Ordering, collections::HashMap, path::PathBuf};
use tokio::sync::broadcast;

/// File thats stores account-level system messages.
pub const SYSTEM_MESSAGES_FILE: &str = "system-messages";

/// Path to the file used to store account-level system messages.
///
/// # Panics
///
/// If this set of paths are global (no user identifier).
pub fn system_messages_path(paths: &Paths) -> PathBuf {
    if paths.is_global() {
        panic!("system messages are not accessible for global paths");
    }
    let mut vault_path = paths.user_dir().join(SYSTEM_MESSAGES_FILE);
    vault_path.set_extension(JSON_EXT);
    vault_path
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
    channel: broadcast::Sender<SysMessageCount>,
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
            path: system_messages_path(paths),
            messages: Default::default(),
            channel: stream_channel(),
        }
    }

    /// Load the system messages stored on disc into memory.
    ///
    /// If the file does not exist this is a noop.
    pub async fn load(&mut self) -> Result<()> {
        if vfs::try_exists(&self.path).await? {
            let content = vfs::read_exclusive(&self.path).await?;
            let sys: SystemMessages = serde_json::from_slice(&content)?;
            self.messages = sys.messages;
        }
        Ok(())
    }

    /// Subscribe to the broadcast channel.
    pub fn subscribe(&self) -> broadcast::Receiver<SysMessageCount> {
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

    /// Message counts.
    pub fn counts(&self) -> SysMessageCount {
        let mut counts: SysMessageCount = Default::default();
        counts.total = self.messages.len();
        for item in self.messages.values() {
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
        self.messages.insert(key, message);
        self.save().await
    }

    /// Mark a message as read.
    ///
    /// Changes are written to disc.
    pub async fn mark_read(&mut self, key: &Urn) -> Result<()> {
        let updated = if let Some(message) = self.messages.get_mut(key) {
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
    pub fn sorted_list(&self) -> Vec<(&Urn, &SysMessage)> {
        let mut messages: Vec<_> = self.messages.iter().collect();
        messages.sort_by(|a, b| a.1.cmp(b.1));
        messages
    }

    /// Save system messages to disc.
    async fn save(&self) -> Result<()> {
        let buf = serde_json::to_vec_pretty(self)?;
        vfs::write_exclusive(&self.path, buf).await?;
        let _ = self.channel.send(self.counts());
        Ok(())
    }
}
