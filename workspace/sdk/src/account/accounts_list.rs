//! List local accounts and find folders.
use std::{fmt, path::PathBuf, str::FromStr};

use serde::{Deserialize, Serialize};
use web3_address::ethereum::Address;

use crate::{
    account::UserPaths,
    constants::VAULT_EXT,
    decode,
    vault::{Header, Summary, Vault, VaultId},
    vfs,
};

use crate::{Error, Result, account::{AccountInfo}};

/// Inspect the local accounts directory.
pub struct AccountsList<'a> {
    paths: &'a UserPaths,
}

impl<'a> AccountsList<'a> {
    /// Create new local accounts.
    pub fn new(paths: &'a UserPaths) -> Self {
        Self { paths }
    }

    /// Find and load a vault for a local file.
    pub async fn find_local_vault(
        &self,
        id: &VaultId,
        include_system: bool,
    ) -> Result<(Vault, PathBuf)> {
        let vaults = self.list_local_vaults(include_system).await?;
        let (_summary, path) = vaults
            .into_iter()
            .find(|(s, _)| s.id() == id)
            .ok_or_else(|| Error::NoVaultFile(id.to_string()))?;

        let buffer = vfs::read(&path).await?;
        let vault: Vault = decode(&buffer).await?;
        Ok((vault, path))
    }

    /// Get a list of the vaults for an account directly from the file system.
    pub async fn list_local_vaults(
        &self,
        include_system: bool,
    ) -> Result<Vec<(Summary, PathBuf)>> {
        let vaults_dir = self.paths.vaults_dir();

        let mut vaults = Vec::new();
        let mut dir = vfs::read_dir(vaults_dir).await?;
        while let Some(entry) = dir.next_entry().await? {
            if let Some(extension) = entry.path().extension() {
                if extension == VAULT_EXT {
                    let summary =
                        Header::read_summary_file(entry.path()).await?;
                    if !include_system && summary.flags().is_system() {
                        continue;
                    }
                    vaults.push((summary, entry.path().to_path_buf()));
                }
            }
        }
        Ok(vaults)
    }
    
    /*
    /// List account information for the identity vaults.
    pub async fn list_accounts(
        paths: Option<&UserPaths>,
    ) -> Result<Vec<AccountInfo>> {
        let mut keys = Vec::new();
        let paths = if let Some(paths) = paths {
            paths.clone()
        } else {
            UserPaths::new_global(UserPaths::data_dir()?)
        };

        let mut dir = vfs::read_dir(paths.identity_dir()).await?;

        while let Some(entry) = dir.next_entry().await? {
            if let (Some(extension), Some(file_stem)) =
                (entry.path().extension(), entry.path().file_stem())
            {
                if extension == VAULT_EXT {
                    let summary =
                        Header::read_summary_file(entry.path()).await?;
                    keys.push(AccountInfo {
                        address: file_stem.to_string_lossy().parse()?,
                        label: summary.name().to_owned(),
                    });
                }
            }
        }
        keys.sort_by(|a, b| a.label.cmp(&b.label));
        Ok(keys)
    }
    */
}
