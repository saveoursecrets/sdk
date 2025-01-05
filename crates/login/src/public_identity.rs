//! Public identity information.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sos_core::{constants::VAULT_EXT, decode, AccountId, Paths, VaultId};
use sos_vault::{Header, Summary, Vault};
use sos_vfs as vfs;
use std::{
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
};

/// Public account identity information.
#[typeshare::typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct PublicIdentity {
    /// Address identifier for the account.
    account_id: AccountId,
    /// Label for the account.
    ///
    /// This is the name given to the identity vault.
    label: String,
}

impl PublicIdentity {
    /// Create new account information.
    pub fn new(label: String, account_id: AccountId) -> Self {
        Self { label, account_id }
    }

    /// Get the account identifier.
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Get the label of this account.
    pub fn label(&self) -> &str {
        &self.label
    }

    pub(crate) fn set_label(&mut self, label: String) {
        self.label = label;
    }

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
            if let Some(ident) =
                Self::read_public_identity(entry.path()).await?
            {
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
                let summary =
                    Header::read_summary_file(path.as_ref()).await?;
                return Ok(Some(PublicIdentity {
                    account_id: file_stem.to_string_lossy().parse()?,
                    label: summary.name().to_owned(),
                }));
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Find and load a vault.
    pub(crate) async fn load_local_vault(
        paths: &Paths,
        id: &VaultId,
    ) -> Result<(Vault, PathBuf)> {
        let folders = Self::list_local_folders(paths).await?;
        let (_summary, path) = folders
            .into_iter()
            .find(|(s, _)| s.id() == id)
            .ok_or_else(|| Error::NoVaultFile(id.to_string()))?;
        let buffer = vfs::read(&path).await?;
        let vault: Vault = decode(&buffer).await?;
        Ok((vault, path))
    }

    /// List the folders in an account by inspecting
    /// the vault files in the vaults directory.
    pub(crate) async fn list_local_folders(
        paths: &Paths,
    ) -> Result<Vec<(Summary, PathBuf)>> {
        let vaults_dir = paths.vaults_dir();
        let mut vaults = Vec::new();
        let mut dir = vfs::read_dir(vaults_dir).await?;
        while let Some(entry) = dir.next_entry().await? {
            if let Some(extension) = entry.path().extension() {
                if extension == VAULT_EXT {
                    let summary =
                        Header::read_summary_file(entry.path()).await?;
                    vaults.push((summary, entry.path().to_path_buf()));
                }
            }
        }
        Ok(vaults)
    }
}

impl From<&PublicIdentity> for AccountRef {
    fn from(value: &PublicIdentity) -> Self {
        AccountRef::Id(*value.account_id())
    }
}

impl From<PublicIdentity> for AccountRef {
    fn from(value: PublicIdentity) -> Self {
        (&value).into()
    }
}

/// Reference to an account using an address or a named label.
#[derive(Debug, Clone)]
pub enum AccountRef {
    /// Account identifier.
    Id(AccountId),
    /// Account label.
    Name(String),
}

impl fmt::Display for AccountRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => write!(f, "{}", id),
            Self::Name(name) => write!(f, "{}", name),
        }
    }
}

impl FromStr for AccountRef {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(id) = s.parse::<AccountId>() {
            Ok(Self::Id(id))
        } else {
            Ok(Self::Name(s.to_string()))
        }
    }
}
