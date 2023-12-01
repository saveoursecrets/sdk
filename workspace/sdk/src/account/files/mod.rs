//! File encryption/decryption and manager for external files.
use crate::{
    account::UserPaths,
    events::FileEvent,
    hex,
    vault::{secret::SecretId, VaultId},
    vfs, Result,
};
use std::{array::TryFromSliceError, collections::HashSet, fmt, path::Path};

mod external_files;
mod external_files_sync;
mod file_manager;

pub use external_files::FileStorage;
pub use external_files_sync::FileStorageSync;
pub use file_manager::{FileProgress, FileSource};

/// Meta data about an encrypted file.
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    /// Size of the encrypted data in bytes.
    pub size: u64,
    /// Sha256 digest of the encrypted buffer.
    pub digest: Vec<u8>,
}

/// External file name is an SHA2-256 checksum of
/// the encrypted file contents.
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub struct ExternalFileName([u8; 32]);

impl From<ExternalFileName> for [u8; 32] {
    fn from(value: ExternalFileName) -> Self {
        value.0
    }
}

impl fmt::Display for ExternalFileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Pointer to an external file.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct ExternalFile(VaultId, SecretId, ExternalFileName);

impl From<ExternalFile> for FileEvent {
    fn from(value: ExternalFile) -> Self {
        FileEvent::CreateFile(value.0, value.1, value.2.to_string())
    }
}

/// List all the external files in an account.
///
/// If a directory name cannot be parsed to a folder or secret
/// identifier or the file name cannot be converted to `[u8; 32]`
/// the directory or file will be ignored.
pub(super) async fn list_external_files(
    paths: &UserPaths,
) -> Result<HashSet<ExternalFile>> {
    let mut files = HashSet::new();
    let mut dir = vfs::read_dir(paths.files_dir()).await?;
    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();
        if path.is_dir() {
            if let Some(file_name) = path.file_name() {
                if let Ok(folder_id) =
                    file_name.to_string_lossy().as_ref().parse::<VaultId>()
                {
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
                                    let mut external_files =
                                        list_secret_files(path).await?;
                                    tracing::debug!(
                                        files_len = external_files.len()
                                    );
                                    for file_name in external_files.drain() {
                                        files.insert(ExternalFile(
                                            folder_id, secret_id, file_name,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(files)
}

async fn list_secret_files(
    path: impl AsRef<Path>,
) -> Result<HashSet<ExternalFileName>> {
    let mut files = HashSet::new();
    let mut dir = vfs::read_dir(path.as_ref()).await?;
    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            if let Some(file_name) = path.file_name() {
                if let Ok(buf) =
                    hex::decode(file_name.to_string_lossy().as_ref())
                {
                    let checksum: std::result::Result<
                        [u8; 32],
                        TryFromSliceError,
                    > = buf.as_slice().try_into();
                    if let Ok(checksum) = checksum {
                        files.insert(ExternalFileName(checksum));
                    } else {
                        tracing::warn!(
                            file_name = %file_name.to_string_lossy().as_ref(),
                            "skip file (not 32 bytes)",
                        );
                    }
                } else {
                    tracing::warn!(
                        file_name = %file_name.to_string_lossy().as_ref(),
                        "skip file (not hex)",
                    );
                }
            }
        }
    }
    Ok(files)
}

/// Compute the file name from a path.
///
/// If no file name is available the returned value is the
/// empty string.
pub fn basename<P: AsRef<Path>>(path: P) -> String {
    path.as_ref()
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Guess the MIME type of a path.
///
/// This implementation supports some more types
/// that are not in the the mime_guess library that
/// we also want to recognize.
pub fn guess_mime<P: AsRef<Path>>(path: P) -> Result<String> {
    if let Some(extension) = path.as_ref().extension() {
        let fixed = match extension.to_string_lossy().as_ref() {
            "heic" => Some("image/heic".to_string()),
            "heif" => Some("image/heif".to_string()),
            "avif" => Some("image/avif".to_string()),
            _ => None,
        };

        if let Some(fixed) = fixed {
            return Ok(fixed);
        }
    }
    let mime = mime_guess::from_path(&path)
        .first_or(mime_guess::mime::APPLICATION_OCTET_STREAM)
        .to_string();
    Ok(mime)
}
