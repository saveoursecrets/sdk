#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Vault encrypted storage and access.
mod access_point;
mod builder;
mod change;
mod encoding;
mod error;
pub mod secret;
mod vault;

pub use access_point::{AccessPoint, SecretAccess};
pub use builder::{BuilderCredentials, VaultBuilder};
pub use change::ChangePassword;
pub use error::Error;
pub use vault::{
    Contents, EncryptedEntry, Header, SharedAccess, Summary, Vault, VaultMeta,
};

// DO NOT USE: these re-exports will be removed in the future
pub use sos_core::{VaultCommit, VaultEntry, VaultFlags, VaultId};

pub(crate) type Result<T> = std::result::Result<T, Error>;
pub(crate) use vault::Auth;

use sos_core::{constants::VAULT_EXT, Paths, PublicIdentity};
use sos_vfs as vfs;
use std::path::{Path, PathBuf};

/// List account information for the identity vaults.
pub async fn list_accounts(
    paths: Option<&Paths>,
) -> Result<Vec<PublicIdentity>> {
    let mut identities = Vec::new();
    let paths = if let Some(paths) = paths {
        paths.clone()
    } else {
        Paths::new_global(Paths::data_dir()?)
    };

    let mut dir = vfs::read_dir(paths.identity_dir()).await?;
    while let Some(entry) = dir.next_entry().await? {
        if let Some(ident) = read_public_identity(entry.path()).await? {
            identities.push(ident);
        }
    }
    identities.sort_by(|a, b| a.label().cmp(b.label()));
    Ok(identities)
}

/// Read the public identity from an identity vault file.
pub async fn read_public_identity(
    path: impl AsRef<Path>,
) -> Result<Option<PublicIdentity>> {
    if let (Some(extension), Some(file_stem)) =
        (path.as_ref().extension(), path.as_ref().file_stem())
    {
        if extension == VAULT_EXT {
            let summary = Header::read_summary_file(path.as_ref()).await?;
            return Ok(Some(PublicIdentity::new(
                file_stem.to_string_lossy().parse()?,
                summary.name().to_owned(),
            )));
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

/// List the folders in an account by inspecting
/// the vault files in the vaults directory.
pub async fn list_local_folders(
    paths: &Paths,
) -> Result<Vec<(Summary, PathBuf)>> {
    let vaults_dir = paths.vaults_dir();
    let mut vaults = Vec::new();
    let mut dir = vfs::read_dir(vaults_dir).await?;
    while let Some(entry) = dir.next_entry().await? {
        if let Some(extension) = entry.path().extension() {
            if extension == VAULT_EXT {
                let summary = Header::read_summary_file(entry.path()).await?;
                vaults.push((summary, entry.path().to_path_buf()));
            }
        }
    }
    Ok(vaults)
}
