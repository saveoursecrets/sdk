//! List local accounts and find folders.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    constants::VAULT_EXT,
    decode,
    sha2::Digest,
    signer::Signer,
    storage::StorageDirs,
    vault::{
        Gatekeeper, Header, Summary, Vault, VaultAccess, VaultFileAccess,
        VaultId,
    },
    wal::WalProvider,
};

use crate::{Error, Result};

/// Combines an account address with a label.
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
pub struct LocalAccounts {}

impl LocalAccounts {
    /*
    /// Verify the master passphrase for an account.
    pub fn verify(address: &str, passphrase: SecretString) -> Result<bool> {
        let identity_path = StorageDirs::identity_vault(address)?;
        let result = Identity::login_file(identity_path, passphrase, None);
        Ok(result.is_ok())
    }
    */

    /// Rename an identity vault.
    ///
    /// The caller should take care to ensure this is only allowed on the
    /// identity vault for the currently authenticated account.
    pub fn rename_identity(
        address: &str,
        account_name: String,
        identity: Option<&mut Gatekeeper>,
    ) -> Result<()> {
        // Update in-memory vault
        if let Some(identity) = identity {
            identity.vault_mut().set_name(account_name.clone());
        }
        // Update vault file on disc
        let identity_vault_file = StorageDirs::identity_vault(address)?;
        let mut access = VaultFileAccess::new(identity_vault_file)?;
        access.set_vault_name(account_name)?;
        Ok(())
    }

    /// Permanently delete the identity vault and local vaults for an account.
    pub fn delete_account(address: &str) -> Result<()> {
        let identity_vault_file = StorageDirs::identity_vault(address)?;

        let local_dir = StorageDirs::local_dir()?;
        let identity_data_dir = local_dir.join(address);

        // FIXME: move to a trash folder
        std::fs::remove_file(identity_vault_file)?;
        std::fs::remove_dir_all(identity_data_dir)?;

        Ok(())
    }

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
