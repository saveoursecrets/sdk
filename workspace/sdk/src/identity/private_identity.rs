//! Private identity manages the identity vault,
//! account signing key, device signing key and delegated 
//! passwords.
use crate::{
    commit::CommitState,
    constants::{
        FILE_PASSWORD_URN, LOGIN_AGE_KEY_URN, LOGIN_SIGNING_KEY_URN,
        VAULT_EXT, VAULT_NSS,
    },
    crypto::{AccessKey, KeyDerivation, SecureAccessKey},
    decode, encode,
    events::{AuditEvent, Event, EventKind},
    identity::UrnLookup,
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

/// Number of words to use when generating passphrases for vaults.
const VAULT_PASSPHRASE_WORDS: usize = 12;

/// Private identity containing the in-memory identity vault
/// and signing keys.
pub struct PrivateIdentity {
    /// Address of the signing key.
    pub(super) address: Address,
    /// Private signing key for the identity.
    pub(super) signer: BoxedEcdsaSigner,
    /// Gatekeeper for the identity vault.
    pub(super) keeper: Arc<RwLock<Gatekeeper>>,
    /// Lookup mapping between folders and
    /// the secret idenitifiers in the identity vault.
    pub(super) index: Arc<RwLock<UrnLookup>>,
    /// AGE identity keypair.
    #[allow(dead_code)]
    pub(super) shared_private: age::x25519::Identity,
    /// AGE recipient public key.
    pub(super) shared_public: age::x25519::Recipient,
    #[cfg(feature = "device")]
    pub(super) devices: Option<crate::device::DeviceManager>,
}

impl PrivateIdentity {
    /// Address of the signing key.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Signing key for this user.
    pub fn signer(&self) -> &BoxedEcdsaSigner {
        &self.signer
    }

    /// Signing key for this device.
    ///
    /// # Panics
    ///
    /// If the device manager has not been initialized.
    #[cfg(feature = "device")]
    pub fn device(&self) -> &DeviceSigner {
        self.devices.as_ref().unwrap().signer()
    }

    /// Reference to the gatekeeper for the identity vault.
    pub fn keeper(&self) -> Arc<RwLock<Gatekeeper>> {
        Arc::clone(&self.keeper)
    }

    /// Search index for the identity vault.
    pub fn index(&self) -> Arc<RwLock<UrnLookup>> {
        Arc::clone(&self.index)
    }

    /// Recipient public key for sharing.
    pub fn recipient(&self) -> &age::x25519::Recipient {
        &self.shared_public
    }

    /// Device manager.
    #[cfg(feature = "device")]
    pub fn devices(&self) -> Result<&DeviceManager> {
        self.devices.as_ref().ok_or(Error::NotAuthenticated)
    }

    /// Device manager.
    #[cfg(feature = "device")]
    pub fn devices_mut(&mut self) -> Result<&mut DeviceManager> {
        self.devices.as_mut().ok_or(Error::NotAuthenticated)
    }

    /// Generate a folder password.
    pub(super) fn generate_folder_password(&self) -> Result<SecretString> {
        let (vault_passphrase, _) =
            generate_passphrase_words(VAULT_PASSPHRASE_WORDS)?;
        Ok(vault_passphrase)
    }

    /// Save a folder password into this identity.
    pub(super) async fn save_folder_password(
        &self,
        vault_id: &VaultId,
        key: AccessKey,
    ) -> Result<()> {
        Self::create_folder_password(
            Arc::clone(&self.keeper),
            Arc::clone(&self.index),
            vault_id,
            key,
        )
        .await
    }

    /// Find a folder password in this identity.
    ///
    /// The identity vault must already be unlocked to extract
    /// the secret password.
    pub(super) async fn find_folder_password(
        &self,
        vault_id: &VaultId,
    ) -> Result<AccessKey> {
        let span = span!(Level::DEBUG, "find_folder_password");
        let _enter = span.enter();

        let urn = Vault::vault_urn(vault_id)?;

        tracing::debug!(folder = %vault_id, urn = %urn);

        let keeper = self.keeper.read().await;
        let index = self.index.read().await;

        let id = index
            .get(&(*keeper.id(), urn.clone()))
            .ok_or_else(|| Error::NoVaultEntry(urn.to_string()))?;

        let (_, secret, _) = keeper
            .read(id)
            .await?
            .ok_or_else(|| Error::NoSecretId(*keeper.id(), *id))?;

        let key = match secret {
            Secret::Password { password, .. } => {
                AccessKey::Password(password)
            }
            Secret::Age { key, .. } => {
                AccessKey::Identity(key.expose_secret().parse().map_err(
                    |s: &str| Error::InvalidX25519Identity(s.to_owned()),
                )?)
            }
            _ => return Err(Error::VaultEntryKind(urn.to_string())),
        };
        Ok(key)
    }

    /// Remove a folder password from this identity.
    pub(super) async fn remove_folder_password(
        &mut self,
        vault_id: &VaultId,
    ) -> Result<()> {
        Self::delete_folder_password(
            Arc::clone(&self.keeper),
            Arc::clone(&self.index),
            vault_id,
        )
        .await
    }

    /// Find the password used for symmetric file encryption (AGE).
    pub(crate) async fn find_file_encryption_password(
        &self,
    ) -> Result<SecretString> {
        let keeper = self.keeper.read().await;
        let reader = self.index.read().await;
        let urn: Urn = FILE_PASSWORD_URN.parse()?;

        let id = reader
            .get(&(*keeper.id(), urn.clone()))
            .ok_or_else(|| Error::NoVaultEntry(urn.to_string()))?;

        let password =
            if let Some((_, Secret::Password { password, .. }, _)) =
                keeper.read(id).await?
            {
                password
            } else {
                return Err(Error::VaultEntryKind(urn.to_string()));
            };
        Ok(password)
    }

    /// Save a folder password into an identity vault.
    pub async fn create_folder_password(
        keeper: Arc<RwLock<Gatekeeper>>,
        index: Arc<RwLock<UrnLookup>>,
        vault_id: &VaultId,
        key: AccessKey,
    ) -> Result<()> {
        let span = span!(Level::DEBUG, "save_folder_password");
        let _enter = span.enter();

        let urn = Vault::vault_urn(vault_id)?;
        tracing::debug!(folder = %vault_id, urn = %urn);

        let secret = match key {
            AccessKey::Password(vault_passphrase) => Secret::Password {
                name: None,
                password: vault_passphrase,
                user_data: Default::default(),
            },
            AccessKey::Identity(id) => Secret::Age {
                version: Default::default(),
                key: id.to_string(),
                user_data: Default::default(),
            },
        };

        let mut meta =
            SecretMeta::new(urn.as_str().to_owned(), secret.kind());
        meta.set_urn(Some(urn.clone()));

        let id = SecretId::new_v4();

        let mut keeper = keeper.write().await;

        let secret_data = SecretRow::new(id, meta, secret);
        keeper.create(&secret_data).await?;

        let mut index = index.write().await;
        index.insert((*keeper.id(), urn), id);

        Ok(())
    }

    /// Remove a folder password from an identity vault.
    pub async fn delete_folder_password(
        keeper: Arc<RwLock<Gatekeeper>>,
        index: Arc<RwLock<UrnLookup>>,
        vault_id: &VaultId,
    ) -> Result<()> {
        tracing::debug!(folder = %vault_id, "remove folder password");

        let (keeper_id, id, urn) = {
            let keeper = keeper.read().await;
            let urn = Vault::vault_urn(vault_id)?;
            let index_reader = index.read().await;
            let id = index_reader
                .get(&(*keeper.id(), urn.clone()))
                .ok_or(Error::NoVaultEntry(urn.to_string()))?;
            (*keeper.id(), *id, urn)
        };

        let mut keeper = keeper.write().await;
        keeper.delete(&id).await?;

        let mut index = index.write().await;
        index.remove(&(keeper_id, urn));

        Ok(())
    }

    /// Sign out the private identity.
    ///
    /// Locks the identity vault and device vault.
    pub async fn sign_out(&mut self) -> Result<()> {
        // Lock the identity vault
        let mut writer = self.keeper.write().await;
        writer.lock();

        // Lock the devices vault
        #[cfg(feature = "device")]
        if let Some(devices) = self.devices.as_mut() {
            devices.sign_out();
        }

        Ok(())
    }
}
