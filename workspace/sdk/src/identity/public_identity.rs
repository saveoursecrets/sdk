//! Public identity information.
use crate::{
    commit::CommitState,
    constants::{
        FILE_PASSWORD_URN, LOGIN_AGE_KEY_URN, LOGIN_SIGNING_KEY_URN,
        VAULT_EXT, VAULT_NSS,
    },
    crypto::{AccessKey, KeyDerivation, SecureAccessKey},
    decode, encode,
    events::{AuditEvent, Event, EventKind},
    identity::PrivateIdentity,
    passwd::diceware::generate_passphrase_words,
    signer::{
        ecdsa::{Address, BoxedEcdsaSigner, SingleParty},
        ed25519, Signer,
    },
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow, SecretSigner},
        Gatekeeper, Header, Summary, Vault, VaultAccess, VaultBuilder,
        VaultFlags, VaultId, VaultWriter,
    },
    vfs, Error, Paths, Result,
};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{span, Level};
use urn::Urn;

#[cfg(feature = "device")]
use crate::device::{DeviceManager, DeviceSigner};

/// Public account identity information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicIdentity {
    /// Address identifier for the account.
    ///
    /// This corresponds to the address of the signing key
    /// for the account.
    address: Address,
    /// Label for the account.
    ///
    /// This is the name given to the identity vault.
    label: String,
}

impl PublicIdentity {
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

    /// List account information for the identity vaults.
    pub async fn list_accounts(
        paths: Option<&Paths>,
    ) -> Result<Vec<PublicIdentity>> {
        let mut keys = Vec::new();
        let paths = if let Some(paths) = paths {
            paths.clone()
        } else {
            Paths::new_global(Paths::data_dir()?)
        };

        let mut dir = vfs::read_dir(paths.identity_dir()).await?;
        while let Some(entry) = dir.next_entry().await? {
            if let (Some(extension), Some(file_stem)) =
                (entry.path().extension(), entry.path().file_stem())
            {
                if extension == VAULT_EXT {
                    let summary =
                        Header::read_summary_file(entry.path()).await?;
                    keys.push(PublicIdentity {
                        address: file_stem.to_string_lossy().parse()?,
                        label: summary.name().to_owned(),
                    });
                }
            }
        }
        keys.sort_by(|a, b| a.label().cmp(b.label()));
        Ok(keys)
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
        AccountRef::Address(*value.address())
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
