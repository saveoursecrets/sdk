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
#[derive(
    Default, Copy, Clone, Hash, Eq, PartialEq, Serialize, Deserialize,
)]
pub struct ExternalFileName(#[serde(with = "hex::serde")] [u8; 32]);

impl fmt::Debug for ExternalFileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ExternalFileName")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl From<ExternalFileName> for [u8; 32] {
    fn from(value: ExternalFileName) -> Self {
        value.0
    }
}

impl AsRef<[u8]> for ExternalFileName {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for ExternalFileName {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl TryFrom<&[u8]> for ExternalFileName {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let value: [u8; 32] = value.try_into()?;
        Ok(value.into())
    }
}

impl fmt::Display for ExternalFileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl FromStr for ExternalFileName {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let buf: [u8; 32] = hex::decode(s)?.as_slice().try_into()?;
        Ok(Self(buf))
    }
}

/// Pointer to an external file.
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub struct ExternalFile(SecretPath, ExternalFileName);

impl From<ExternalFile> for FileEvent {
    fn from(value: ExternalFile) -> Self {
        FileEvent::CreateFile(value.0, value.1)
    }
}

impl From<ExternalFile> for (SecretPath, ExternalFileName) {
    fn from(value: ExternalFile) -> Self {
        (value.0, value.1)
    }
}

impl ExternalFile {
    /// Create a new external file reference.
    pub fn new(path: SecretPath, file_name: ExternalFileName) -> Self {
        Self(path, file_name)
    }

    /// Vault identifier.
    pub fn vault_id(&self) -> &VaultId {
        &self.0 .0
    }

    /// Secret identifier.
    pub fn secret_id(&self) -> &SecretId {
        &self.0 .1
    }

    /// File name.
    pub fn file_name(&self) -> &ExternalFileName {
        &self.1
    }
}

impl fmt::Display for ExternalFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.vault_id(),
            self.secret_id(),
            self.file_name()
        )
    }
}

impl FromStr for ExternalFile {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.splitn(3, '/');
        let vault_id = parts
            .next()
            .ok_or(Error::InvalidExternalFile(s.to_owned()))?;
        let secret_id = parts
            .next()
            .ok_or(Error::InvalidExternalFile(s.to_owned()))?;
        let file_name = parts
            .next()
            .ok_or(Error::InvalidExternalFile(s.to_owned()))?;
        let vault_id: VaultId = vault_id.parse()?;
        let secret_id: SecretId = secret_id.parse()?;
        let file_name: ExternalFileName = file_name.parse()?;
        Ok(Self(SecretPath(vault_id, secret_id), file_name))
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
                            files.insert(ExternalFile(
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
