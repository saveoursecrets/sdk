//! List local accounts and find folders.
use std::{fmt, path::PathBuf, str::FromStr};

use serde::{Deserialize, Serialize};
use web3_address::ethereum::Address;

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
    address: Address,
    /// User label for the account.
    ///
    /// This is the name given to the identity vault.
    label: String,
}

impl AccountInfo {
    /// Create new account information.
    pub fn new(label: String, address: Address) -> Self {
        Self { label, address }
    }

    /// Get the address of this account.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get the label of this account.
    pub fn label(&self) -> &str {
        &self.label
    }

    pub(crate) fn set_label(&mut self, label: String) {
        self.label = label;
    }
}

impl From<&AccountInfo> for AccountRef {
    fn from(value: &AccountInfo) -> Self {
        AccountRef::Address(*value.address())
    }
}

impl From<AccountInfo> for AccountRef {
    fn from(value: AccountInfo) -> Self {
        (&value).into()
    }
}

/// Reference to an account using an address or a named label.
#[derive(Debug, Clone)]
pub enum AccountRef {
    /// Account identifier.
    Address(Address),
    /// Account label.
    Name(String),
}

impl fmt::Display for AccountRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(address) => write!(f, "{}", address),
            Self::Name(name) => write!(f, "{}", name),
        }
    }
}

impl FromStr for AccountRef {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(address) = s.parse::<Address>() {
            Ok(Self::Address(address))
        } else {
            Ok(Self::Name(s.to_string()))
        }
    }
}

/// Inspect the local accounts directory.
#[derive(Default)]
pub struct LocalAccounts;

impl LocalAccounts {
    /// Find and load a vault for a local file.
    pub fn find_local_vault(
        address: &Address,
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

    /// Get a list of the vaults for an account directly from the file system.
    pub fn list_local_vaults(
        address: &Address,
        include_system: bool,
    ) -> Result<Vec<(Summary, PathBuf)>> {
        let vaults_dir = StorageDirs::local_vaults_dir(address.to_string())?;
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
                        address: file_stem.to_string_lossy().parse()?,
                        label: summary.name().to_owned(),
                    });
                }
            }
        }
        keys.sort_by(|a, b| a.label.cmp(&b.label));
        Ok(keys)
    }
}
