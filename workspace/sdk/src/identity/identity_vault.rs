//! Login identity vault management.
//!
//! Provides access to an identity vault containing
//! the account signing key and delegated passwords used
//! for folders managed by an account.
//!
//! This enables user interfaces to protect both the signing
//! key and folder passwords using a single master password.
use crate::{
    commit::CommitState,
    constants::{
        FILE_PASSWORD_URN, LOGIN_AGE_KEY_URN, LOGIN_SIGNING_KEY_URN,
        VAULT_EXT, VAULT_NSS,
    },
    crypto::{AccessKey, KeyDerivation},
    decode, encode,
    events::{AuditEvent, Event, EventKind},
    identity::{PrivateIdentity, UrnLookup},
    passwd::diceware::generate_passphrase_words,
    signer::{
        ecdsa::{Address, BoxedEcdsaSigner, SingleParty},
        ed25519, Signer,
    },
    vault::{
        secret::{
            Secret, SecretId, SecretMeta, SecretRow, SecretSigner, UserData,
        },
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

/// Identity vault stores the account signing key,
/// asymmetric encryption key and delegated passwords.
pub struct IdentityVault {
    keeper: Gatekeeper,
    index: UrnLookup,
    private_identity: PrivateIdentity,
    #[cfg(feature = "device")]
    pub(super) devices: Option<crate::device::DeviceManager>,
}

impl IdentityVault {
    /// Private identity.
    pub fn private_identity(&self) -> &PrivateIdentity {
        &self.private_identity
    }

    /// Signing key for this user.
    pub fn signer(&self) -> &BoxedEcdsaSigner {
        self.private_identity.signer()
    }

    /// Account address.
    pub fn address(&self) -> &Address {
        self.private_identity.address()
    }

    /// Gatekeeper of the identity vault.
    pub fn keeper(&self) -> &Gatekeeper {
        &self.keeper
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

    /// Create a new identity vault with a primary password.
    ///
    /// Generates a new random single party signing key and
    /// a public identity key for asymmetric encryption and
    /// stores them in the identity vault.
    pub async fn new(name: String, password: SecretString) -> Result<Self> {
        let vault = VaultBuilder::new()
            .public_name(name)
            .flags(VaultFlags::IDENTITY)
            .password(password.clone(), Some(KeyDerivation::generate_seed()))
            .await?;

        let mut keeper = Gatekeeper::new(vault);
        let key: AccessKey = password.into();
        keeper.unlock(&key).await?;

        // Store the signing key
        let signer = SingleParty::new_random();
        let address = signer.address()?;
        let private_key =
            SecretSigner::SinglePartyEcdsa(SecretVec::new(signer.to_bytes()));
        let signer_secret = Secret::Signer {
            private_key,
            user_data: Default::default(),
        };
        let signer_urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
        let mut signer_meta = SecretMeta::new(
            signer_urn.as_str().to_owned(),
            signer_secret.kind(),
        );
        signer_meta.set_urn(Some(signer_urn.clone()));

        let signer_id = SecretId::new_v4();
        let secret_data =
            SecretRow::new(signer_id, signer_meta, signer_secret);
        keeper.create(&secret_data).await?;

        // Store the AGE identity
        let identity_id = SecretId::new_v4();
        let shared = age::x25519::Identity::generate();
        let age_secret = Secret::Age {
            version: Default::default(),
            key: shared.to_string(),
            user_data: Default::default(),
        };
        let identity_urn: Urn = LOGIN_AGE_KEY_URN.parse()?;
        let mut age_meta = SecretMeta::new(
            identity_urn.as_str().to_owned(),
            age_secret.kind(),
        );
        age_meta.set_urn(Some(identity_urn.clone()));

        let secret_data = SecretRow::new(identity_id, age_meta, age_secret);
        keeper.create(&secret_data).await?;

        let private_identity = PrivateIdentity {
            address,
            signer: Box::new(signer),
            shared_public: shared.to_public(),
            shared_private: shared,
        };

        let mut index: UrnLookup = Default::default();
        index.insert((*keeper.id(), signer_urn), signer_id);
        index.insert((*keeper.id(), identity_urn), identity_id);

        Ok(Self {
            keeper,
            index,
            private_identity,
            #[cfg(feature = "device")]
            devices: None,
        })
    }

    /// Rename this identity vault.
    pub async fn rename(&mut self, account_name: String) -> Result<()> {
        self.keeper.set_vault_name(account_name.clone()).await?;
        Ok(())
    }

    /// Login to an identity vault.
    pub async fn login<P: AsRef<Path>>(
        file: P,
        key: &AccessKey,
    ) -> Result<Self> {
        let vault_file = VaultWriter::open(file.as_ref()).await?;
        let mirror = VaultWriter::new(file.as_ref(), vault_file)?;
        let buffer = vfs::read(file.as_ref()).await?;
        Self::login_buffer(buffer, key, Some(mirror)).await
    }

    /// Attempt to login using a buffer.
    pub(crate) async fn login_buffer<B: AsRef<[u8]>>(
        buffer: B,
        key: &AccessKey,
        mirror: Option<VaultWriter<vfs::File>>,
    ) -> Result<Self> {
        let vault: Vault = decode(buffer.as_ref()).await?;
        if !vault.flags().contains(VaultFlags::IDENTITY) {
            return Err(Error::NotIdentityVault);
        }

        let mut keeper = if let Some(mirror) = mirror {
            Gatekeeper::new_mirror(vault, mirror)
        } else {
            Gatekeeper::new(vault)
        };

        keeper.unlock(&key).await?;

        let mut index: UrnLookup = Default::default();

        let signer_urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
        let identity_urn: Urn = LOGIN_AGE_KEY_URN.parse()?;

        let mut signer_secret: Option<Secret> = None;
        let mut identity_secret: Option<Secret> = None;
        let mut folder_secrets = HashMap::new();

        for id in keeper.vault().keys() {
            if let Some((meta, secret, _)) = keeper.read(id).await? {
                if let Some(urn) = meta.urn() {
                    if urn.nss().starts_with(VAULT_NSS) {
                        let id: VaultId = urn
                            .nss()
                            .trim_start_matches(VAULT_NSS)
                            .parse()?;
                        if let Secret::Password { password, .. } = &secret {
                            let key: AccessKey = password.clone().into();
                            folder_secrets.insert(id, key);
                        }
                    }

                    if urn == &signer_urn {
                        signer_secret = Some(secret);
                    } else if urn == &identity_urn {
                        identity_secret = Some(secret);
                    }

                    // Add to the URN lookup index
                    index.insert((*keeper.id(), urn.clone()), *id);
                }
            }
        }

        for id in keeper.vault().keys() {
            if let Some((meta, secret, _)) = keeper.read(id).await? {
                if let Some(urn) = meta.urn() {
                    if urn.nss().starts_with(VAULT_NSS) {
                        let id: VaultId = urn
                            .nss()
                            .trim_start_matches(VAULT_NSS)
                            .parse()?;
                        if let Secret::Password { password, .. } = &secret {
                            let key: AccessKey = password.clone().into();
                        }
                    }

                    if urn == &signer_urn {
                        signer_secret = Some(secret);
                    } else if urn == &identity_urn {
                        identity_secret = Some(secret);
                    }

                    // Add to the URN lookup index
                    index.insert((*keeper.id(), urn.clone()), *id);
                }
            }
        }

        let signer = signer_secret.ok_or(Error::NoSigningKey)?;
        let identity = identity_secret.ok_or(Error::NoIdentityKey)?;

        // Account signing key extraction
        let signer = if let Secret::Signer { private_key, .. } = signer {
            Some(private_key.try_into_ecdsa_signer()?)
        } else {
            None
        };
        let signer = signer.ok_or(Error::NoSigningKey)?;
        let address = signer.address()?;

        // Identity key extraction
        let identity = if let Secret::Age { key, .. } = identity {
            let identity: age::x25519::Identity =
                key.expose_secret().parse().map_err(|s: &'static str| {
                    Error::AgeIdentityParse(s.to_string())
                })?;
            Some(identity)
        } else {
            None
        };
        let shared = identity.ok_or(Error::NoIdentityKey)?;

        let private_identity = PrivateIdentity {
            address,
            signer,
            shared_public: shared.to_public(),
            shared_private: shared,
        };

        Ok(Self {
            keeper,
            index,
            private_identity,
            #[cfg(feature = "device")]
            devices: None,
        })
    }

    /// Ensure that the account has a vault for storing device specific
    /// information such as the private key used to identify a machine
    /// and the account's trusted devices.
    #[cfg(feature = "device")]
    pub(super) async fn ensure_device_vault(
        &mut self,
        paths: &Paths,
    ) -> Result<()> {
        use crate::constants::DEVICE_KEY_URN;
        let device_vault_path = paths.devices_file().to_owned();

        let device_vault = if vfs::try_exists(&device_vault_path).await? {
            let buffer = vfs::read(&device_vault_path).await?;
            let vault: Vault = decode(&buffer).await?;
            Some(vault)
        } else {
            None
        };

        let device_key_urn: Urn = DEVICE_KEY_URN.parse()?;
        let device_manager = if let Some(vault) = device_vault {
            let summary = vault.summary().clone();
            let device_password =
                self.find_folder_password(summary.id()).await?;

            let vault_file = VaultWriter::open(&device_vault_path).await?;
            let mirror = VaultWriter::new(&device_vault_path, vault_file)?;

            let mut device_keeper = Gatekeeper::new_mirror(vault, mirror);
            let key: AccessKey = device_password.into();
            device_keeper.unlock(&key).await?;

            let mut device_signer_secret: Option<Secret> = None;
            {
                for id in device_keeper.vault().keys() {
                    if let Some((meta, secret, _)) =
                        device_keeper.read(id).await?
                    {
                        if let Some(urn) = meta.urn() {
                            if urn == &device_key_urn {
                                device_signer_secret = Some(secret);
                            }
                            // Add to the URN lookup index
                            self.index.insert(
                                (*device_keeper.id(), urn.clone()),
                                *id,
                            );
                        }
                    }
                }
            }

            if let Some(Secret::Signer {
                private_key: SecretSigner::SinglePartyEd25519(data),
                ..
            }) = device_signer_secret
            {
                let key: ed25519::SingleParty =
                    data.expose_secret().as_slice().try_into()?;
                Ok(DeviceManager::new(key.into(), device_keeper))
            } else {
                Err(Error::VaultEntryKind(device_key_urn.to_string()))
            }
        } else {
            // Prepare the passphrase for the device vault
            let device_password = self.generate_folder_password()?;

            // Prepare the device vault
            let vault = VaultBuilder::new()
                .public_name("Device".to_string())
                .flags(
                    VaultFlags::SYSTEM
                        | VaultFlags::DEVICE
                        | VaultFlags::NO_SYNC_SELF
                        | VaultFlags::NO_SYNC_OTHER,
                )
                .password(device_password.clone().into(), None)
                .await?;

            self.save_folder_password(
                vault.id(),
                device_password.clone().into(),
            )
            .await?;

            let buffer = encode(&vault).await?;
            vfs::write(&device_vault_path, &buffer).await?;
            let vault_file = VaultWriter::open(&device_vault_path).await?;
            let mirror = VaultWriter::new(&device_vault_path, vault_file)?;

            let mut device_keeper = Gatekeeper::new_mirror(vault, mirror);
            let key: AccessKey = device_password.into();
            device_keeper.unlock(&key).await?;

            let signer = DeviceSigner::new_random();
            let secret = Secret::Signer {
                private_key: SecretSigner::SinglePartyEd25519(
                    SecretVec::new(signer.signing_key().to_bytes()),
                ),
                user_data: Default::default(),
            };
            let mut meta =
                SecretMeta::new("Device Key".to_string(), secret.kind());
            meta.set_urn(Some(device_key_urn.clone()));

            let id = SecretId::new_v4();
            let secret_data = SecretRow::new(id, meta, secret);
            device_keeper.create(&secret_data).await?;

            {
                self.index.insert((*device_keeper.id(), device_key_urn), id);
            }

            Ok(DeviceManager::new(signer, device_keeper))
        };

        let mut device_manager = device_manager?;
        device_manager.load().await?;

        self.devices = Some(device_manager);
        Ok(())
    }

    /// Generate a folder password.
    pub(super) fn generate_folder_password(&self) -> Result<SecretString> {
        let (vault_passphrase, _) =
            generate_passphrase_words(VAULT_PASSPHRASE_WORDS)?;
        Ok(vault_passphrase)
    }

    /// Save a folder password into this identity.
    pub(super) async fn save_folder_password(
        &mut self,
        vault_id: &VaultId,
        key: AccessKey,
    ) -> Result<()> {
        Self::create_folder_password(
            &mut self.keeper,
            &mut self.index,
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

        let id = self
            .index
            .get(&(*self.keeper.id(), urn.clone()))
            .ok_or_else(|| Error::NoVaultEntry(urn.to_string()))?;

        let (_, secret, _) = self
            .keeper
            .read(id)
            .await?
            .ok_or_else(|| Error::NoSecretId(*self.keeper.id(), *id))?;

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
            &mut self.keeper,
            &mut self.index,
            vault_id,
        )
        .await
    }

    pub(crate) async fn create_file_encryption_password(
        &mut self,
    ) -> Result<()> {
        let file_passphrase = self.generate_folder_password()?;
        let secret = Secret::Password {
            password: file_passphrase,
            name: None,
            user_data: UserData::new_comment(self.address().to_string()),
        };
        let mut meta =
            SecretMeta::new("File Encryption".to_string(), secret.kind());
        let urn: Urn = FILE_PASSWORD_URN.parse()?;
        meta.set_urn(Some(urn.clone()));

        let secret_id = SecretId::new_v4();
        let secret_data = SecretRow::new(secret_id, meta, secret);
        self.keeper.create(&secret_data).await?;
        self.index.insert((*self.keeper.id(), urn), secret_id);

        Ok(())
    }

    /// Find the password used for symmetric file encryption (AGE).
    pub(crate) async fn find_file_encryption_password(
        &self,
    ) -> Result<SecretString> {
        let urn: Urn = FILE_PASSWORD_URN.parse()?;

        let id = self
            .index
            .get(&(*self.keeper.id(), urn.clone()))
            .ok_or_else(|| Error::NoVaultEntry(urn.to_string()))?;

        let password =
            if let Some((_, Secret::Password { password, .. }, _)) =
                self.keeper.read(id).await?
            {
                password
            } else {
                return Err(Error::VaultEntryKind(urn.to_string()));
            };
        Ok(password)
    }

    /// Save a folder password into an identity vault.
    pub async fn create_folder_password(
        keeper: &mut Gatekeeper,
        index: &mut UrnLookup,
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

        let secret_data = SecretRow::new(id, meta, secret);
        keeper.create(&secret_data).await?;

        index.insert((*keeper.id(), urn), id);

        Ok(())
    }

    /// Remove a folder password from an identity vault.
    pub async fn delete_folder_password(
        keeper: &mut Gatekeeper,
        index: &mut UrnLookup,
        vault_id: &VaultId,
    ) -> Result<()> {
        tracing::debug!(folder = %vault_id, "remove folder password");

        let (keeper_id, id, urn) = {
            let urn = Vault::vault_urn(vault_id)?;
            let id = index
                .get(&(*keeper.id(), urn.clone()))
                .ok_or(Error::NoVaultEntry(urn.to_string()))?;
            (*keeper.id(), *id, urn)
        };

        keeper.delete(&id).await?;
        index.remove(&(keeper_id, urn));

        Ok(())
    }

    /// Sign out the identity vault.
    ///
    /// Locks the identity vault and device vault.
    pub async fn sign_out(&mut self) -> Result<()> {
        tracing::debug!("identity vault sign out");

        // Lock the identity vault
        self.keeper.lock();
        self.index = Default::default();

        // Lock the devices vault
        #[cfg(feature = "device")]
        if let Some(devices) = self.devices.as_mut() {
            devices.sign_out();
        }

        Ok(())
    }
}

impl From<IdentityVault> for (Address, Vault) {
    fn from(value: IdentityVault) -> Self {
        (value.address().clone(), value.keeper.into())
    }
}
