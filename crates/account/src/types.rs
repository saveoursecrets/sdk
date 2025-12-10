//! Account management types.
use sos_backend::AccessPoint;
use sos_core::{SecretId, commit::CommitState, events::Event};
use sos_login::PublicIdentity;
use sos_vault::Summary;
use std::sync::Arc;

#[cfg(feature = "search")]
use sos_search::SearchIndex;

#[cfg(feature = "files")]
use sos_external_files::FileMutationEvent;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[cfg(feature = "clipboard")]
use serde_json_path::JsonPath;

/// Clipboard text formatter.
#[cfg(feature = "clipboard")]
#[typeshare::typeshare]
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind",
    content = "body"
)]
pub enum ClipboardTextFormat {
    /// Parse as a RFC3339 date string and
    /// format according to the given format string.
    Date {
        /// Format string.

        // Typeshare doesn't respect rename_all_fields
        #[serde(rename = "formatDescription")]
        format_description: String,
    },
}

/// Request a clipboard copy operation.
#[cfg(feature = "clipboard")]
#[typeshare::typeshare]
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ClipboardCopyRequest {
    /// Target paths.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<JsonPath>>,
    /// Format option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<ClipboardTextFormat>,
}

/// Result information for a change to an account.
pub struct AccountChange<T> {
    /// Event to be logged.
    pub event: Event,
    /// Result generated during a sync.
    pub sync_result: T,
}

/// Result information for a created or updated secret.
pub struct SecretChange<T> {
    /// Secret identifier.
    pub id: SecretId,
    /// Event to be logged.
    pub event: Event,
    /// Commit state of the folder event log before
    /// the secret was created (or updated).
    pub commit_state: CommitState,
    /// Folder containing the secret.
    pub folder: Summary,
    /// Result generated during a sync.
    pub sync_result: T,
    /// File mutation events.
    #[cfg(feature = "files")]
    pub file_events: Vec<FileMutationEvent>,
}

/// Result information for a bulk insert.
pub struct SecretInsert<T> {
    /// Created secrets.
    pub results: Vec<SecretChange<T>>,
    /// Result generated during a sync.
    pub sync_result: T,
}

/// Result information for a secret move event.
pub struct SecretMove<T> {
    /// Secret identifier.
    pub id: SecretId,
    /// Event to be logged.
    pub event: Event,
    /// Result generated during a sync.
    pub sync_result: T,
    /// File mutation events.
    #[cfg(feature = "files")]
    pub file_events: Vec<FileMutationEvent>,
}

/// Result information for a deleted secret.
pub struct SecretDelete<T> {
    /// Event to be logged.
    pub event: Event,
    /// Commit state of the folder event log before
    /// the secret was deleted.
    pub commit_state: CommitState,
    /// Folder the secret was deleted from.
    pub folder: Summary,
    /// Result generated during a sync.
    pub sync_result: T,
    /// File mutation events.
    #[cfg(feature = "files")]
    pub file_events: Vec<FileMutationEvent>,
}

/// Result information for folder creation.
pub struct FolderCreate<T> {
    /// Created folder.
    pub folder: Summary,
    /// Event to be logged.
    pub event: Event,
    /// Commit state of the new folder.
    pub commit_state: CommitState,
    /// Result generated during a sync.
    pub sync_result: T,
}

/// Result information for changes to a folder's attributes.
pub struct FolderChange<T> {
    /// Event to be logged.
    pub event: Event,
    /// Commit state before the change.
    pub commit_state: CommitState,
    /// Result generated during a sync.
    pub sync_result: T,
}

/// Result information for folder deletion.
pub struct FolderDelete<T> {
    /// Events to be logged.
    pub events: Vec<Event>,
    /// Commit state of the folder.
    pub commit_state: CommitState,
    /// Result generated during a sync.
    pub sync_result: T,
}

/// Progress event when importing contacts.
#[cfg(feature = "contacts")]
pub enum ContactImportProgress {
    /// Progress event when the number of contacts is known.
    Ready {
        /// Total number of contacts.
        total: usize,
    },
    /// Progress event when a contact is being imported.
    Item {
        /// Label of the contact.
        label: String,
        /// Index of the contact.
        index: usize,
    },
}

/// Read-only view created from a specific event log commit.
pub struct DetachedView {
    pub(crate) keeper: AccessPoint,
    #[cfg(feature = "search")]
    pub(crate) index: Arc<RwLock<SearchIndex>>,
}

impl DetachedView {
    /// Read-only access to the folder.
    pub fn keeper(&self) -> &AccessPoint {
        &self.keeper
    }

    /// Search index for the detached view.
    #[cfg(feature = "search")]
    pub fn index(&self) -> Arc<RwLock<SearchIndex>> {
        Arc::clone(&self.index)
    }
}

/// Data about an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountData {
    /// Main account information.
    #[serde(flatten)]
    pub account: PublicIdentity,
    /// AGE identity public recipient.
    pub identity: String,
    /// Account folders.
    pub folders: Vec<Summary>,
    /// Identifier of the device public key.
    pub device_id: String,
}
