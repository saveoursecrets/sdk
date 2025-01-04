//! Types for file management.
use crate::Result;
use indexmap::IndexSet;
use sos_core::events::FileEvent;
use sos_core::{
    ExternalFile, ExternalFileName, Paths, SecretId, SecretPath, VaultId,
};
use sos_sdk::{vault::secret::Secret, vfs};
use std::path::{Path, PathBuf};

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

/// List all the external files in an account by reading the
/// state from disc.
///
/// If a directory name cannot be parsed to a folder or secret
/// identifier or the file name cannot be converted to `[u8; 32]`
/// the directory or file will be ignored.
#[doc(hidden)]
pub async fn list_external_files(
    paths: &Paths,
) -> Result<IndexSet<ExternalFile>> {
    let mut files = IndexSet::new();
    let mut dir = vfs::read_dir(paths.files_dir()).await?;
    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();
        if path.is_dir() {
            if let Some(file_name) = path.file_name() {
                if let Ok(folder_id) =
                    file_name.to_string_lossy().as_ref().parse::<VaultId>()
                {
                    let mut folder_files =
                        list_folder_files(paths, &folder_id).await?;
                    for (secret_id, mut external_files) in
                        folder_files.drain(..)
                    {
                        for file_name in external_files.drain(..) {
                            files.insert(ExternalFile::new(
                                SecretPath(folder_id, secret_id),
                                file_name,
                            ));
                        }
                    }
                }
            }
        }
    }
    Ok(files)
}

/// List all the external files in a folder.
///
/// If a directory name cannot be parsed to a folder or secret
/// identifier or the file name cannot be converted to `[u8; 32]`
/// the directory or file will be ignored.
pub async fn list_folder_files(
    paths: &Paths,
    folder_id: &VaultId,
) -> Result<Vec<(SecretId, IndexSet<ExternalFileName>)>> {
    let mut files = Vec::new();
    let path = paths.files_dir().join(folder_id.to_string());

    if vfs::try_exists(&path).await? {
        let mut folder_dir = vfs::read_dir(path).await?;
        while let Some(entry) = folder_dir.next_entry().await? {
            let path = entry.path();
            if path.is_dir() {
                if let Some(file_name) = path.file_name() {
                    tracing::debug!(file_name = ?file_name);
                    if let Ok(secret_id) = file_name
                        .to_string_lossy()
                        .as_ref()
                        .parse::<SecretId>()
                    {
                        let external_files = list_secret_files(path).await?;
                        // tracing::debug!(files_len = external_files.len());
                        files.push((secret_id, external_files));
                    }
                }
            }
        }
    }

    Ok(files)
}

async fn list_secret_files(
    path: impl AsRef<Path>,
) -> Result<IndexSet<ExternalFileName>> {
    let mut files = IndexSet::new();
    let mut dir = vfs::read_dir(path.as_ref()).await?;
    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            if let Some(file_name) = path.file_name() {
                if let Ok(name) = file_name
                    .to_string_lossy()
                    .as_ref()
                    .parse::<ExternalFileName>()
                {
                    files.insert(name);
                } else {
                    tracing::warn!(
                        file_name = %file_name.to_string_lossy().as_ref(),
                        "skip file (invalid file name)",
                    );
                }
            }
        }
    }
    Ok(files)
}
