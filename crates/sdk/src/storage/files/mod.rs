//! File encryption/decryption and manager for external files.
use crate::{
    events::FileEvent,
    hex,
    vault::{
        secret::{SecretId, SecretPath},
        VaultId,
    },
    vfs, Error, Paths, Result,
};
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use std::{fmt, path::Path, str::FromStr};

mod external_files;
mod file_manager;

pub use external_files::FileStorage;
pub use file_manager::{FileMutationEvent, FileProgress, FileSource};

pub use sos_core::{ExternalFile, ExternalFileName};

/// Meta data about an encrypted file.
#[derive(Debug, Clone)]
pub struct EncryptedFile {
    /// Size of the encrypted data in bytes.
    pub size: u64,
    /// Sha256 digest of the encrypted buffer.
    pub digest: Vec<u8>,
}

impl From<ExternalFile> for FileEvent {
    fn from(value: ExternalFile) -> Self {
        let (path, name) = value.into();
        FileEvent::CreateFile(path, name)
    }
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
pub(crate) async fn list_folder_files(
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
