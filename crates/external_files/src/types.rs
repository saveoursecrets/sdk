//! Types for file management.
use sos_core::events::FileEvent;
use sos_vault::secret::Secret;
use std::path::PathBuf;

/// Meta data about an encrypted file.
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    /// Size of the encrypted data in bytes.
    pub size: u64,
    /// Sha256 digest of the encrypted buffer.
    pub digest: Vec<u8>,
}

/// File progress operations.
#[derive(Debug)]
pub enum FileProgress {
    /// File is being written.
    Write {
        /// File name.
        name: String,
    },
    /// File is being moved.
    Move {
        /// File name.
        name: String,
    },
    /// File is being deleted.
    Delete {
        /// File name.
        name: String,
    },
}

/// Diff of file secrets.
#[derive(Debug)]
pub struct FileStorageDiff<'a> {
    /// File secrets that have been deleted.
    pub deleted: Vec<&'a Secret>,
    /// File secrets that have not changed.
    pub unchanged: Vec<&'a Secret>,
}

/// Source path to a file.
#[derive(Debug, Clone)]
pub struct FileSource {
    /// Path to the source file.
    pub path: PathBuf,
    /// Name of the file.
    pub name: String,
    /// Field index for attachments.
    pub field_index: Option<usize>,
}

/// Result of encrypting an external file.
#[derive(Debug, Clone)]
pub struct FileStorageResult {
    /// Source for the file.
    pub source: FileSource,
    /// Encrypted file data.
    pub encrypted_file: EncryptedFile,
}

/// Wraps the file storage information and a
/// related file event that can be persisted
/// to an event log.
#[derive(Debug, Clone)]
pub enum FileMutationEvent {
    /// File was created.
    Create {
        /// Information the created file.
        result: FileStorageResult,
        /// An event that can be persisted to an event log.
        event: FileEvent,
    },
    /// File was moved.
    Move(FileEvent),
    /// File was deleted.
    Delete(FileEvent),
}
