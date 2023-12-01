//! File encryption/decryption and manager for external files.
use crate::{
    account::UserPaths,
    vault::{secret::SecretId, VaultId},
    vfs, Result,
};
use std::{collections::HashSet, path::Path};

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

/// Pointer to an external file.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct ExternalFile(VaultId, SecretId, ExternalFileName);

/// List all the external files in an account.
pub async fn list_external_files(
    paths: &UserPaths,
) -> Result<HashSet<ExternalFile>> {
    let mut files = HashSet::new();
    let mut dir = vfs::read_dir(paths.files_dir()).await?;
    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();
        if path.is_dir() {
            if let Some(file_name) = path.file_name() {
                let folder_id: VaultId =
                    file_name.to_string_lossy().as_ref().parse()?;
                let mut folder_dir = vfs::read_dir(path).await?;
                while let Some(entry) = folder_dir.next_entry().await? {
                    let path = entry.path();
                    if path.is_dir() {
                        if let Some(file_name) = path.file_name() {
                            let secret_id: SecretId = file_name
                                .to_string_lossy()
                                .as_ref()
                                .parse()?;
                            let mut external_files =
                                list_secret_files(path).await?;
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
                let checksum: [u8; 32] = file_name
                    .to_string_lossy()
                    .as_ref()
                    .as_bytes()
                    .try_into()?;
                files.insert(ExternalFileName(checksum));
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
