//! Login identity vault management.
//!
//! Provides access to an identity vault containing
//! the account signing key and delegated passwords used
//! for folders managed by an account.
//!
//! This enables user interfaces to protect both the signing
//! key and encryption passphrase using a single master
//! passphrase.
use secrecy::{ExposeSecret, SecretString, SecretVec};

use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

use std::path::Path;

use serde::{Deserialize, Serialize};
use urn::Urn;
use web3_address::ethereum::Address;

use crate::{
    account::{AccountInfo, LocalAccount, UserPaths},
    commit::CommitState,
    constants::{
        DEVICE_KEY_URN, FILE_PASSWORD_URN, LOGIN_AGE_KEY_URN,
        LOGIN_SIGNING_KEY_URN, VAULT_EXT,
    },
    crypto::{AccessKey, KeyDerivation, SecureAccessKey},
    decode, encode,
    events::{AuditEvent, Event, EventKind},
    passwd::diceware::generate_passphrase_words,
    signer::{
        ecdsa::{BoxedEcdsaSigner, SingleParty},
        ed25519, Signer,
    },
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow, SecretSigner},
        Gatekeeper, Summary, Vault, VaultAccess, VaultBuilder, VaultFlags,
        VaultId, VaultWriter,
    },
    vfs, Error, Result,
};

use tracing::{span, Level};

#[cfg(feature = "device")]
use crate::account::DeviceSigner;

/// Number of words to use when generating passphrases for vaults.
const VAULT_PASSPHRASE_WORDS: usize = 12;

/// Collection of folder access keys.
pub struct FolderKeys(pub HashMap<Summary, AccessKey>);

impl FolderKeys {
    /// Find an access key by folder id.
    pub fn find(&self, id: &VaultId) -> Option<&AccessKey> {
        self.0
            .iter()
            .find_map(|(k, v)| if k.id() == id { Some(v) } else { None })
    }
}

/// Collection of secure access keys.
#[derive(Default, Clone)]
pub struct SecureKeys(HashMap<VaultId, SecureAccessKey>);

impl SecureKeys {
    /// Number of folders with secure access keys.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this collection is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Iterator for the secure access keys.
    pub fn iter(&self) -> impl Iterator<Item = (&VaultId, &SecureAccessKey)> {
        self.0.iter()
    }

    /// Find an access key by folder id.
    pub fn find(&self, id: &VaultId) -> Option<&SecureAccessKey> {
        self.0
            .iter()
            .find_map(|(k, v)| if k == id { Some(v) } else { None })
    }
}

/// Cache of mapping between secret URN
/// and secret identifiers to we can find identity
/// vault secrets quickly.
pub type UrnLookup = HashMap<(VaultId, Urn), SecretId>;

/// Identity manages access to an identity vault
/// and the private keys for a user.
pub struct Identity {
    paths: UserPaths,
    account: Option<AccountInfo>,
    identity: Option<PrivateIdentity>,
    secure_keys: SecureKeys,
}

impl Identity {
    /// Create a new unauthenticated user.
    pub fn new(paths: UserPaths) -> Self {
        Self {
            paths,
            identity: None,
            account: None,
            secure_keys: Default::default(),
        }
    }

    /// Collection of secure access keys for folders
    /// managed by this identity.
    pub fn secure_keys(&self) -> &SecureKeys {
        &self.secure_keys
    }

    /// Account information.
    pub fn account(&self) -> Result<&AccountInfo> {
        self.account.as_ref().ok_or(Error::NotAuthenticated)
    }

    fn account_mut(&mut self) -> Result<&mut AccountInfo> {
        self.account.as_mut().ok_or(Error::NotAuthenticated)
    }

    /// Private identity.
    pub fn identity(&self) -> Result<&PrivateIdentity> {
        self.identity.as_ref().ok_or(Error::NotAuthenticated)
    }

    fn identity_mut(&mut self) -> Result<&mut PrivateIdentity> {
        self.identity.as_mut().ok_or(Error::NotAuthenticated)
    }

    /// Account signing key.
    pub(crate) fn signing_key(&self) -> Result<BoxedEcdsaSigner> {
        Ok(self
            .identity
            .as_ref()
            .ok_or(Error::NotAuthenticated)?
            .signer
            .clone())
    }

    /// Verify the passphrase for this account.
    pub async fn verify(&self, key: &AccessKey) -> bool {
        if let Some(identity) = &self.identity {
            let keeper = identity.keeper();
            let reader = keeper.read().await;
            let result = reader.verify(key).await.ok();
            result.is_some()
        } else {
            false
        }
    }

    /// Delete the account for this user.
    pub async fn delete_account(&self, paths: &UserPaths) -> Result<Event> {
        vfs::remove_file(paths.identity_vault()).await?;
        vfs::remove_dir_all(paths.user_dir()).await?;

        let event = Event::CreateAccount(AuditEvent::new(
            EventKind::DeleteAccount,
            self.identity()?.address().clone(),
            None,
        ));

        Ok(event)
    }

    /// Rename this account by changing the name of the identity vault.
    pub async fn rename_account(
        &mut self,
        paths: &UserPaths,
        account_name: String,
    ) -> Result<()> {
        // Update in-memory vault
        {
            let keeper = self.identity()?.keeper();
            let mut writer = keeper.write().await;
            writer.vault_mut().set_name(account_name.clone());
        }

        // Update vault file on disc
        let identity_vault_file = paths.identity_vault();

        let vault_file = VaultWriter::open(&identity_vault_file).await?;
        let mut access = VaultWriter::new(identity_vault_file, vault_file)?;
        access.set_vault_name(account_name.clone()).await?;

        // Update in-memory account information
        self.account_mut()?.set_label(account_name);

        Ok(())
    }

    /// Generate a folder password.
    pub fn generate_folder_password(&self) -> Result<SecretString> {
        self.identity()?.generate_folder_password()
    }

    /// Save a folder password into an identity vault.
    pub async fn save_folder_password(
        &mut self,
        vault_id: &VaultId,
        key: AccessKey,
    ) -> Result<()> {
        let secure_key = self.to_secure_access_key(&key).await?;
        self.identity_mut()?
            .save_folder_password(vault_id, key)
            .await?;
        self.secure_keys.0.insert(*vault_id, secure_key);
        Ok(())
    }

    /// Remove a folder password from an identity vault.
    pub async fn remove_folder_password(
        &mut self,
        vault_id: &VaultId,
    ) -> Result<()> {
        self.identity_mut()?
            .remove_folder_password(vault_id)
            .await?;
        self.secure_keys.0.remove(vault_id);
        Ok(())
    }

    /// Find a folder access key and encrypt it using the
    /// account signing key.
    pub fn find_secure_access_key(
        &self,
        vault_id: &VaultId,
    ) -> Result<&SecureAccessKey> {
        Ok(self.secure_keys.0.get(vault_id).ok_or(Error::NoSecureAccessKey(*vault_id))?)
    }

    /// Convert a secret key to a secure access key.
    pub(crate) async fn to_secure_access_key(
        &self,
        folder_password: &AccessKey,
    ) -> Result<SecureAccessKey> {
        let secret_key = self.signing_key()?.to_bytes();
        Ok(SecureAccessKey::encrypt(folder_password, &secret_key, None)
            .await?)
    }

    /// Find a folder password in an identity vault.
    ///
    /// The identity vault must already be unlocked to extract
    /// the secret passphrase.
    pub async fn find_folder_password(
        &self,
        vault_id: &VaultId,
    ) -> Result<AccessKey> {
        self.identity()?.find_folder_password(vault_id).await
    }

    /// Find the password used for symmetric file encryption (AGE).
    pub(crate) async fn find_file_encryption_password(
        &self,
    ) -> Result<SecretString> {
        self.identity()?.find_file_encryption_password().await
    }

    /// Create a new login vault with a master password.
    ///
    /// Generates a new random single party signing key and
    /// a public identity key for asymmetric encryption and
    /// stores them in the identity vault.
    pub async fn new_login_vault(
        name: String,
        password: SecretString,
    ) -> Result<(Address, Vault)> {
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
        let urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
        let mut signer_meta =
            SecretMeta::new(urn.as_str().to_owned(), signer_secret.kind());
        signer_meta.set_urn(Some(urn));

        let secret_data =
            SecretRow::new(SecretId::new_v4(), signer_meta, signer_secret);
        keeper.create(&secret_data).await?;

        // Store the AGE identity
        let age_secret = Secret::Age {
            version: Default::default(),
            key: age::x25519::Identity::generate().to_string(),
            user_data: Default::default(),
        };
        let urn: Urn = LOGIN_AGE_KEY_URN.parse()?;
        let mut age_meta =
            SecretMeta::new(urn.as_str().to_owned(), age_secret.kind());
        age_meta.set_urn(Some(urn));

        let secret_data =
            SecretRow::new(SecretId::new_v4(), age_meta, age_secret);
        keeper.create(&secret_data).await?;

        Ok((address, keeper.into()))
    }

    /// Login to an identity vault.
    pub async fn login<P: AsRef<Path>>(
        &mut self,
        file: P,
        key: &AccessKey,
    ) -> Result<()> {
        let vault_file = VaultWriter::open(file.as_ref()).await?;
        let mirror = VaultWriter::new(file.as_ref(), vault_file)?;
        let buffer = vfs::read(file.as_ref()).await?;
        self.login_buffer(buffer, key, Some(mirror)).await
    }

    /// Attempt to login using a buffer.
    pub(crate) async fn login_buffer<B: AsRef<[u8]>>(
        &mut self,
        buffer: B,
        key: &AccessKey,
        mirror: Option<VaultWriter<vfs::File>>,
    ) -> Result<()> {
        let vault: Vault = decode(buffer.as_ref()).await?;
        if !vault.flags().contains(VaultFlags::IDENTITY) {
            return Err(Error::NotIdentityVault);
        }

        let mut keeper = if let Some(mirror) = mirror {
            Gatekeeper::new_mirror(vault, mirror)
        } else {
            Gatekeeper::new(vault)
        };

        //let key: AccessKey = password.into();
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
                    if urn.nss().starts_with("vault:") {
                        let id: VaultId =
                            urn.nss().trim_start_matches("vault:").parse()?;
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
                    if urn.nss().starts_with("vault:") {
                        let id: VaultId =
                            urn.nss().trim_start_matches("vault:").parse()?;
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

        self.identity = Some(PrivateIdentity {
            address,
            signer,
            #[cfg(feature = "device")]
            device: None,
            shared_public: shared.to_public(),
            shared_private: shared,
            keeper: Arc::new(RwLock::new(keeper)),
            index: Arc::new(RwLock::new(index)),
        });

        // Load folder secure access keys after we have
        // the signing key
        for (id, key) in folder_secrets {
            let secure_access_key = self.to_secure_access_key(&key).await?;
            self.secure_keys.0.insert(id, secure_access_key);
        }

        Ok(())
    }

    /// Sign in to a user account.
    pub async fn sign_in(
        &mut self,
        address: &Address,
        key: &AccessKey,
    ) -> Result<()> {
        let span = span!(Level::DEBUG, "login");
        let _enter = span.enter();

        let accounts = LocalAccount::list_accounts(Some(&self.paths)).await?;
        let account = accounts
            .into_iter()
            .find(|a| a.address() == address)
            .ok_or_else(|| Error::NoAccount(address.to_string()))?;

        let identity_path = self.paths.identity_vault();

        tracing::debug!(identity_path = ?identity_path);

        self.login(identity_path, key).await?;

        tracing::debug!("identity verified");

        // Lazily create or retrieve a device specific signing key
        #[cfg(feature = "device")]
        {
            let device = self.ensure_device_vault().await?;
            let identity = self.identity.as_mut().unwrap();
            identity.device = Some(device);
        }

        self.account = Some(account);
        Ok(())
    }

    /// Ensure that the account has a vault for storing device specific
    /// information such as the private key used to identify a machine.
    #[cfg(feature = "device")]
    async fn ensure_device_vault(&mut self) -> Result<DeviceSigner> {
        let vaults =
            LocalAccount::list_local_folders(&self.paths, true).await?;

        let device_vault = vaults.into_iter().find_map(|(summary, _)| {
            if summary.flags().is_system() && summary.flags().is_device() {
                Some(summary)
            } else {
                None
            }
        });

        let device_key_urn: Urn = DEVICE_KEY_URN.parse()?;

        if let Some(summary) = device_vault {
            let device_password =
                self.find_folder_password(summary.id()).await?;

            let (vault, _) = LocalAccount::load_local_vault(
                &self.paths,
                summary.id(),
                true,
            )
            .await?;
            let search_index = self.identity()?.index();
            let mut device_keeper = Gatekeeper::new(vault);
            let key: AccessKey = device_password.into();
            device_keeper.unlock(&key).await?;

            let mut device_signer_secret: Option<Secret> = None;

            {
                let mut index = search_index.write().await;
                for id in device_keeper.vault().keys() {
                    if let Some((meta, secret, _)) =
                        device_keeper.read(id).await?
                    {
                        if let Some(urn) = meta.urn() {
                            if urn == &device_key_urn {
                                device_signer_secret = Some(secret);
                            }
                            // Add to the URN lookup index
                            index.insert(
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
                let public_id = key.address()?;
                Ok(DeviceSigner {
                    summary,
                    signer: Box::new(key),
                    public_id,
                })
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

            let mut device_keeper = Gatekeeper::new(vault);
            let key: AccessKey = device_password.into();
            device_keeper.unlock(&key).await?;

            let key = ed25519::SingleParty::new_random();
            let public_id = key.address()?;

            let secret = Secret::Signer {
                private_key: key.clone().into(),
                user_data: Default::default(),
            };
            let mut meta =
                SecretMeta::new("Device Key".to_string(), secret.kind());
            meta.set_urn(Some(device_key_urn.clone()));
            let id = SecretId::new_v4();

            let secret_data = SecretRow::new(id, meta, secret);
            device_keeper.create(&secret_data).await?;

            {
                let search = self.identity_mut()?.index();
                let mut index = search.write().await;
                index.insert((*device_keeper.id(), device_key_urn), id);
            }

            let device_vault: Vault = device_keeper.into();
            let summary = device_vault.summary().clone();

            let buffer = encode(&device_vault).await?;
            let vaults_dir = self.paths.vaults_dir();
            let mut device_vault_file =
                vaults_dir.join(summary.id().to_string());
            device_vault_file.set_extension(VAULT_EXT);

            vfs::write(device_vault_file, buffer).await?;

            Ok(DeviceSigner {
                summary,
                signer: Box::new(key),
                public_id,
            })
        }
    }

    /// Sign out this user by locking the account identity vault.
    pub async fn sign_out(&mut self) -> Result<()> {
        tracing::debug!("identity vault sign out");
        let keeper = self.identity()?.keeper();
        let mut writer = keeper.write().await;
        writer.lock();

        self.account = None;
        self.identity = None;
        self.secure_keys = Default::default();
        Ok(())
    }
}

/// Private identity containing the in-memory identity vault
/// and signing keys.
pub struct PrivateIdentity {
    /// Address of the signing key.
    address: Address,
    /// Private signing key for the identity.
    signer: BoxedEcdsaSigner,
    /// Gatekeeper for the identity vault.
    keeper: Arc<RwLock<Gatekeeper>>,
    /// Lookup mapping between folders and
    /// the secret idenitifiers in the identity vault.
    index: Arc<RwLock<UrnLookup>>,
    /// AGE identity keypair.
    #[allow(dead_code)]
    shared_private: age::x25519::Identity,
    /// AGE recipient public key.
    shared_public: age::x25519::Recipient,
    #[cfg(feature = "device")]
    device: Option<DeviceSigner>,
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

    /// Device signing key.
    #[cfg(feature = "device")]
    pub fn device(&self) -> Result<&DeviceSigner> {
        self.device.as_ref().ok_or(Error::NoDevice)
    }

    /// Generate a folder password.
    fn generate_folder_password(&self) -> Result<SecretString> {
        let (vault_passphrase, _) =
            generate_passphrase_words(VAULT_PASSPHRASE_WORDS)?;
        Ok(vault_passphrase)
    }

    /// Save a folder password into this identity.
    async fn save_folder_password(
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
    async fn find_folder_password(
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
    async fn remove_folder_password(
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
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use secrecy::{ExposeSecret, SecretString};
    use std::path::PathBuf;
    use urn::Urn;

    use crate::{
        account::{Identity, UserPaths},
        constants::LOGIN_SIGNING_KEY_URN,
        crypto::AccessKey,
        encode,
        passwd::diceware::generate_passphrase,
        vault::{
            secret::{Secret, SecretId, SecretMeta, SecretRow},
            Gatekeeper, Vault, VaultBuilder, VaultFlags,
        },
        Error,
    };

    #[tokio::test]
    async fn identity_not_identity_vault() -> Result<()> {
        let (password, _) = generate_passphrase()?;
        let vault =
            VaultBuilder::new().password(password.clone(), None).await?;
        let buffer = encode(&vault).await?;

        let mut identity =
            Identity::new(UserPaths::new_global(UserPaths::data_dir()?));
        let key: AccessKey = password.into();
        let result = identity.login_buffer(buffer, &key, None).await;
        if let Err(Error::NotIdentityVault) = result {
            Ok(())
        } else {
            panic!("expecting identity vault error");
        }
    }

    #[tokio::test]
    async fn no_signing_key() -> Result<()> {
        let (password, _) = generate_passphrase()?;

        let vault = VaultBuilder::new()
            .flags(VaultFlags::IDENTITY)
            .password(password.clone(), None)
            .await?;

        let buffer = encode(&vault).await?;

        let mut identity =
            Identity::new(UserPaths::new_global(UserPaths::data_dir()?));
        let key: AccessKey = password.into();
        let result = identity.login_buffer(buffer, &key, None).await;
        if let Err(Error::NoSigningKey) = result {
            Ok(())
        } else {
            panic!("expecting no identity signer error");
        }
    }

    #[tokio::test]
    async fn no_identity_key() -> Result<()> {
        let (password, _) = generate_passphrase()?;

        let vault = VaultBuilder::new()
            .flags(VaultFlags::IDENTITY)
            .password(password.clone(), None)
            .await?;

        let mut keeper = Gatekeeper::new(vault);
        let key = password.clone().into();
        keeper.unlock(&key).await?;

        // Create a secret using the expected name but of the wrong kind
        let signer_secret = Secret::Note {
            text: SecretString::new("Mock note".to_owned()),
            user_data: Default::default(),
        };

        let urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
        let mut signer_meta =
            SecretMeta::new(urn.as_str().to_owned(), signer_secret.kind());
        signer_meta.set_urn(Some(urn));
        let secret_data =
            SecretRow::new(SecretId::new_v4(), signer_meta, signer_secret);
        keeper.create(&secret_data).await?;

        let vault: Vault = keeper.into();
        let buffer = encode(&vault).await?;

        let mut identity =
            Identity::new(UserPaths::new_global(UserPaths::data_dir()?));
        let key: AccessKey = password.into();
        let result = identity.login_buffer(buffer, &key, None).await;
        if let Err(Error::NoIdentityKey) = result {
            Ok(())
        } else {
            panic!("expecting identity signer kind error");
        }
    }
}
