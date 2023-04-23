//! List local accounts and find folders.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    constants::VAULT_EXT,
    decode,
    storage::StorageDirs,
    vault::{Header, Summary, Vault, VaultId},
};

use crate::{Error, Result};

/// Basic account information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountInfo {
    /// Address identifier for the account.
    ///
    /// This corresponds to the address of the signing key
    /// for the account.
    pub address: String,
    /// User label for the account.
    ///
    /// This is the name given to the identity vault.
    pub label: String,
}

/// Inspect the local accounts directory.
#[derive(Default)]
pub struct LocalAccounts;

impl LocalAccounts {
    /// Find and load a vault for a local file.
    pub fn find_local_vault(
        address: &str,
        id: &VaultId,
        include_system: bool,
    ) -> Result<(Vault, PathBuf)> {
        let vaults = Self::list_local_vaults(address, include_system)?;
        let (_summary, path) = vaults
            .into_iter()
            .find(|(s, _)| s.id() == id)
            .ok_or_else(|| Error::NoVaultFile(id.to_string()))?;

        let buffer = std::fs::read(&path)?;
        let vault: Vault = decode(&buffer)?;
        Ok((vault, path))
    }

    /// Find the default vault for an account.
    pub fn find_default_vault(address: &str) -> Result<(Summary, PathBuf)> {
        let vaults = Self::list_local_vaults(address, false)?;
        let (summary, path) = vaults
            .into_iter()
            .find(|(s, _)| s.flags().is_default())
            .ok_or_else(|| Error::NoDefaultVault(address.to_string()))?;
        Ok((summary, path))
    }

    /// Get a list of the vaults for an account directly from the file system.
    pub fn list_local_vaults(
        address: &str,
        include_system: bool,
    ) -> Result<Vec<(Summary, PathBuf)>> {
        let vaults_dir = StorageDirs::local_vaults_dir(address)?;
        let mut vaults = Vec::new();
        for entry in std::fs::read_dir(vaults_dir)? {
            let entry = entry?;
            if let Some(extension) = entry.path().extension() {
                if extension == VAULT_EXT {
                    let summary = Header::read_summary_file(entry.path())?;
                    if !include_system && summary.flags().is_system() {
                        continue;
                    }
                    vaults.push((summary, entry.path().to_path_buf()));
                }
            }
        }
        Ok(vaults)
    }

    /// List account information for the identity vaults.
    pub fn list_accounts() -> Result<Vec<AccountInfo>> {
        let mut keys = Vec::new();
        let identity_dir = StorageDirs::identity_dir()?;
        for entry in std::fs::read_dir(identity_dir)? {
            let entry = entry?;
            if let (Some(extension), Some(file_stem)) =
                (entry.path().extension(), entry.path().file_stem())
            {
                if extension == VAULT_EXT {
                    let summary = Header::read_summary_file(entry.path())?;
                    keys.push(AccountInfo {
                        address: file_stem.to_string_lossy().into_owned(),
                        label: summary.name().to_owned(),
                    });
                }
            }
        }
        keys.sort_by(|a, b| a.label.cmp(&b.label));
        Ok(keys)
    }
}
