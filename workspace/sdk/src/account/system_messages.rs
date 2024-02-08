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
use crate::{vfs, Paths, Result};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf, cmp::Ordering};
use time::OffsetDateTime;

/// System message notification.
#[derive(Debug, Serialize, Deserialize, Ord, Eq, PartialEq)]
pub struct Message {
    /// Date and time the message was created.
    pub created: OffsetDateTime,
    /// Message priority impacts the ordering.
    pub priority: usize,
    /// Title for the message.
    pub title: String,
    /// Content of the message.
    pub content: String,
    /// Indicates if the message has been read.
    pub is_read: bool,
}
impl PartialOrd for Message {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.created.cmp(&other.created))
    }
}

/// Persistent system message notifications.
#[derive(Debug, Serialize, Deserialize)]
pub struct SystemMessages {
    #[serde(flatten)]
    messages: HashMap<String, Message>,
    /// Path to the file on disc.
    #[serde(skip)]
    path: PathBuf,
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
        }
    }

    /// Load the system messages stored on disc into memory.
    pub async fn load(&mut self) -> Result<()> {
        let content = vfs::read(&self.path).await?;
        let sys: SystemMessages = serde_json::from_slice(&content)?;
        self.messages = sys.messages;
        Ok(())
    }

    /// Create or overwrite a system message.
    ///
    /// Changes are written to disc.
    pub async fn insert(
        &mut self,
        key: String,
        message: Message,
    ) -> Result<()> {
        self.messages.insert(key, message);
        self.save().await
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
    pub fn sorted_list(&self) -> Vec<&Message> {
        let mut messages: Vec<_> = self.messages.values().collect();
        messages.sort();
        messages
    }

    /// Save system messages to disc.
    async fn save(&self) -> Result<()> {
        let buf = serde_json::to_vec_pretty(self)?;
        vfs::write(&self.path, buf).await?;
        Ok(())
    }
}
