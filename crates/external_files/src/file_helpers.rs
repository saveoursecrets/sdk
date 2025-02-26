//! Helper functions for reading external files from the
//! file system.
use indexmap::IndexSet;
use sos_core::{
    ExternalFile, ExternalFileName, Paths, SecretId, SecretPath, VaultId,
};
use sos_vfs as vfs;
use std::path::{Path, PathBuf};

type Result<T> = std::result::Result<T, sos_core::Error>;

/// List all the external files in an account by reading the
/// state from disc.
///
/// If a directory name cannot be parsed to a folder or secret
/// identifier or the file name cannot be converted to `[u8; 32]`
/// the directory or file will be ignored.
///
/// This is an implementation for the v1 file system backend that
/// stores external files in the account directories. For the newer
/// v2 layout for the SQLite update use `list_external_blobs`.
pub async fn list_external_files(
    paths: &Paths,
) -> Result<IndexSet<ExternalFile>> {
    list_account(paths.files_dir(), |folder_id| {
        paths.into_file_folder_path(&folder_id)
    })
    .await
}

#[doc(hidden)]
pub async fn list_external_blobs(
    paths: &Paths,
) -> Result<IndexSet<ExternalFile>> {
    list_account(paths.blobs_account_dir(), |folder_id| {
        paths.into_file_folder_path(&folder_id)
    })
    .await
}

#[doc(hidden)]
pub async fn list_folder_blobs(
    paths: &Paths,
    folder_id: &VaultId,
) -> Result<Vec<(SecretId, IndexSet<ExternalFileName>)>> {
    list_folder(paths.into_file_folder_path(folder_id)).await
}

/// List all the external files in a folder.
///
/// If a directory name cannot be parsed to a folder or secret
/// identifier or the file name cannot be converted to `[u8; 32]`
/// the directory or file will be ignored.
///
/// This is an implementation for the v1 file system backend that
/// stores external files in the account directories. For the newer
/// v2 layout for the SQLite update use `list_folder_blobs`.
pub async fn list_folder_files(
    paths: &Paths,
    folder_id: &VaultId,
) -> Result<Vec<(SecretId, IndexSet<ExternalFileName>)>> {
    list_folder(paths.into_file_folder_path(folder_id)).await
}

async fn list_account<F>(
    path: impl AsRef<Path>,
    func: F,
) -> Result<IndexSet<ExternalFile>>
where
    F: Fn(VaultId) -> PathBuf,
{
    let mut files = IndexSet::new();
    let mut dir = vfs::read_dir(path.as_ref()).await?;
    while let Some(entry) = dir.next_entry().await? {
        let path = entry.path();
        if path.is_dir() {
            if let Some(file_name) = path.file_name() {
                if let Ok(folder_id) =
                    file_name.to_string_lossy().as_ref().parse::<VaultId>()
                {
                    let mut folder_files =
                        list_folder(func(folder_id)).await?;

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

async fn list_folder(
    path: impl AsRef<Path>,
) -> Result<Vec<(SecretId, IndexSet<ExternalFileName>)>> {
    let mut files = Vec::new();
    if vfs::try_exists(path.as_ref()).await? {
        let mut folder_dir = vfs::read_dir(path.as_ref()).await?;
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
