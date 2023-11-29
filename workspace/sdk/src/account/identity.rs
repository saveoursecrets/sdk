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
    account::{search::SearchIndex, AccountInfo, AccountsList, UserPaths},
    commit::CommitState,
    constants::{
        DEVICE_KEY_URN, FILE_PASSWORD_URN, LOGIN_AGE_KEY_URN,
        LOGIN_SIGNING_KEY_URN, VAULT_EXT,
    },
    crypto::{AccessKey, KeyDerivation},
    decode, encode,
    events::{AuditEvent, Event, EventKind},
    passwd::diceware::generate_passphrase_words,
    signer::{
        ecdsa::{BoxedEcdsaSigner, SingleParty},
        ed25519, Signer,
    },
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretSigner},
        Gatekeeper, Vault, VaultAccess, VaultBuilder, VaultFlags, VaultId,
        VaultWriter,
    },
    vfs, Error, Result,
};

use tracing::{span, Level};

#[cfg(feature = "device")]
use crate::account::DeviceSigner;

/// Number of words to use when generating passphrases for vaults.
const VAULT_PASSPHRASE_WORDS: usize = 12;

/// User provides access to an identity vault.
pub struct AuthenticatedUser {
    paths: UserPaths,
    account: Option<AccountInfo>,
    identity: Option<PrivateIdentity>,
}

impl AuthenticatedUser {
    /// Create a new unauthenticated user.
    pub fn new(paths: UserPaths) -> Self {
        Self {
            paths,
            identity: None,
            account: None,
        }
    }

    /// Take the private identity from this user.
    pub fn private_identity(mut self) -> Result<PrivateIdentity> {
        self.identity.take().ok_or(Error::NotAuthenticated)
    }

    /// Account information.
    pub fn account(&self) -> Result<&AccountInfo> {
        self.account.as_ref().ok_or(Error::NotAuthenticated)
    }

    fn account_mut(&mut self) -> Result<&mut AccountInfo> {
        self.account.as_mut().ok_or(Error::NotAuthenticated)
    }

    /// User identity reference.
    pub fn identity(&self) -> Result<&PrivateIdentity> {
        self.identity.as_ref().ok_or(Error::NotAuthenticated)
    }

    fn identity_mut(&mut self) -> Result<&mut PrivateIdentity> {
        self.identity.as_mut().ok_or(Error::NotAuthenticated)
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
        self.identity_mut()?
            .save_folder_password(vault_id, key)
            .await
    }

    /// Remove a folder password from an identity vault.
    pub async fn remove_folder_password(
        &mut self,
        vault_id: &VaultId,
    ) -> Result<()> {
        self.identity_mut()?.remove_folder_password(vault_id).await
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

    /// Create a new login vault with a master passphrase.
    ///
    /// Generates a new random single party signing key and
    /// stores it in the new vault along with an encryption
    /// passphrase to use for vaults accessed by this identity.
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
        keeper.unlock(password.into()).await?;

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

        keeper
            .create(SecretId::new_v4(), signer_meta, signer_secret)
            .await?;

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

        keeper
            .create(SecretId::new_v4(), age_meta, age_secret)
            .await?;

        Ok((address, keeper.into()))
    }

    /// Login to an identity vault.
    pub async fn login<P: AsRef<Path>>(
        &mut self,
        file: P,
        password: SecretString,
    ) -> Result<()> {
        let buffer = vfs::read(file.as_ref()).await?;
        self.login_buffer(buffer, password).await
    }

    /// Attempt to login using a buffer.
    pub(crate) async fn login_buffer<B: AsRef<[u8]>>(
        &mut self,
        buffer: B,
        password: SecretString,
    ) -> Result<()> {
        let vault: Vault = decode(buffer.as_ref()).await?;

        if !vault.flags().contains(VaultFlags::IDENTITY) {
            return Err(Error::NotIdentityVault);
        }

        let mut keeper = Gatekeeper::new(vault);

        let mut index = SearchIndex::new();
        keeper.unlock(password.into()).await?;
        index.add_folder(&keeper).await?;

        let urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
        let document = index
            .find_by_urn(keeper.id(), &urn)
            .ok_or(Error::NoSecretUrn(*keeper.id(), urn))?;
        let data = keeper
            .read(document.id())
            .await?
            .ok_or(Error::NoSecretId(*keeper.id(), *document.id()))?;

        let (_, secret, _) = data;

        let signer = if let Secret::Signer { private_key, .. } = secret {
            Some(private_key.try_into_ecdsa_signer()?)
        } else {
            None
        };
        let signer = signer
            .ok_or(Error::WrongSecretKind(*keeper.id(), *document.id()))?;
        let address = signer.address()?;

        let urn: Urn = LOGIN_AGE_KEY_URN.parse()?;
        let document = index
            .find_by_urn(keeper.id(), &urn)
            .ok_or(Error::NoSecretUrn(*keeper.id(), urn))?;
        let data = keeper
            .read(document.id())
            .await?
            .ok_or(Error::NoSecretId(*keeper.id(), *document.id()))?;

        let (_, secret, _) = data;

        let identity = if let Secret::Age { key, .. } = secret {
            let identity: age::x25519::Identity =
                key.expose_secret().parse().map_err(|s: &'static str| {
                    Error::AgeIdentityParse(s.to_string())
                })?;
            Some(identity)
        } else {
            None
        };
        let shared = identity
            .ok_or(Error::WrongSecretKind(*keeper.id(), *document.id()))?;

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

        Ok(())
    }

    /// Sign in to a user account.
    pub async fn sign_in(
        &mut self,
        address: &Address,
        passphrase: SecretString,
    ) -> Result<()> {
        let span = span!(Level::DEBUG, "login");
        let _enter = span.enter();

        let accounts = AccountsList::list_accounts(Some(&self.paths)).await?;
        let account = accounts
            .into_iter()
            .find(|a| a.address() == address)
            .ok_or_else(|| Error::NoAccount(address.to_string()))?;

        let identity_path = self.paths.identity_vault();

        tracing::debug!(identity_path = ?identity_path);

        self.login(identity_path, passphrase).await?;

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
    /// information such as the private key used to identify a machine
    /// on a peer to peer network.
    #[cfg(feature = "device")]
    async fn ensure_device_vault(&mut self) -> Result<DeviceSigner> {
        let local_accounts = AccountsList::new(&self.paths);
        let vaults = local_accounts.list_local_vaults(true).await?;
        let device_vault = vaults.into_iter().find_map(|(summary, _)| {
            if summary.flags().is_system() && summary.flags().is_device() {
                Some(summary)
            } else {
                None
            }
        });

        let urn: Urn = DEVICE_KEY_URN.parse()?;

        let index = self.identity()?.index();

        if let Some(summary) = device_vault {
            let device_passphrase =
                self.find_folder_password(summary.id()).await?;

            let (vault, _) =
                local_accounts.find_local_vault(summary.id(), true).await?;
            let search_index = self.identity()?.index();
            let mut device_keeper = Gatekeeper::new(vault);
            device_keeper.unlock(device_passphrase.into()).await?;
            {
                let mut index = search_index.write().await;
                index.add_folder(&device_keeper).await?;
            }

            let index_reader = index.read().await;
            let document = index_reader
                .find_by_urn(summary.id(), &urn)
                .ok_or(Error::NoVaultEntry(urn.to_string()))?;

            if let Some((
                _,
                Secret::Signer {
                    private_key: SecretSigner::SinglePartyEd25519(data),
                    ..
                },
                _,
            )) = device_keeper.read(document.id()).await?
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
                Err(Error::VaultEntryKind(urn.to_string()))
            }
        } else {
            // Prepare the passphrase for the device vault
            let device_passphrase = self.generate_folder_password()?;

            // Prepare the device vault
            let vault = VaultBuilder::new()
                .public_name("Device".to_string())
                .flags(
                    VaultFlags::SYSTEM
                        | VaultFlags::DEVICE
                        | VaultFlags::NO_SYNC_SELF
                        | VaultFlags::NO_SYNC_OTHER,
                )
                .password(device_passphrase.clone().into(), None)
                .await?;

            /*
            let mut vault: Vault = Default::default();
            vault.set_name("Device".to_string());
            vault.set_system_flag(true);
            vault.set_device_flag(true);
            vault.set_no_sync_self_flag(true);
            vault.set_no_sync_other_flag(true);
            vault.initialize(device_passphrase.clone(), None).await?;
            */

            self.save_folder_password(
                vault.id(),
                device_passphrase.clone().into(),
            )
            .await?;

            let mut device_keeper = Gatekeeper::new(vault);
            device_keeper.unlock(device_passphrase.into()).await?;

            let key = ed25519::SingleParty::new_random();
            let public_id = key.address()?;

            let secret = Secret::Signer {
                private_key: key.clone().into(),
                user_data: Default::default(),
            };
            let mut meta =
                SecretMeta::new("Device Key".to_string(), secret.kind());
            meta.set_urn(Some(urn));
            device_keeper
                .create(SecretId::new_v4(), meta, secret)
                .await?;

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
        Ok(())
    }
}

/// Provides a status overview of an account.
///
/// Intended to be used during a synchronization protocol.
#[derive(Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default)]
pub struct AccountStatus {
    /// Indicates whether the account exists.
    pub exists: bool,
    /// Commit proofs for the account vaults.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub proofs: HashMap<VaultId, CommitState>,
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
    /// Search index for the user identity.
    index: Arc<RwLock<SearchIndex>>,
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
    pub fn index(&self) -> Arc<RwLock<SearchIndex>> {
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
    pub fn generate_folder_password(&self) -> Result<SecretString> {
        let (vault_passphrase, _) =
            generate_passphrase_words(VAULT_PASSPHRASE_WORDS)?;
        Ok(vault_passphrase)
    }

    /// Save a folder password into an identity vault.
    pub async fn save_folder_password(
        &mut self,
        vault_id: &VaultId,
        key: AccessKey,
    ) -> Result<()> {
        let urn = Vault::vault_urn(vault_id)?;

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
        meta.set_urn(Some(urn));

        let id = SecretId::new_v4();

        let index_doc = {
            let index = self.index.read().await;
            index.prepare(vault_id, &id, &meta, &secret)
        };

        let mut keeper = self.keeper.write().await;
        keeper.create(id, meta, secret).await?;

        {
            let mut index = self.index.write().await;
            index.commit(index_doc);
        }

        Ok(())
    }

    /// Remove a folder password from an identity vault.
    pub async fn remove_folder_password(
        &mut self,
        vault_id: &VaultId,
    ) -> Result<()> {
        let id = {
            let keeper = self.keeper.read().await;
            let urn = Vault::vault_urn(vault_id)?;
            let index_reader = self.index.read().await;
            let document = index_reader
                .find_by_urn(keeper.id(), &urn)
                .ok_or(Error::NoVaultEntry(urn.to_string()))?;

            *document.id()
        };

        let mut keeper = self.keeper.write().await;
        keeper.delete(&id).await?;

        {
            let mut index = self.index.write().await;
            index.remove(vault_id, &id);
        }

        Ok(())
    }

    /// Find a folder password in an identity vault.
    ///
    /// The identity vault must already be unlocked to extract
    /// the secret passphrase.
    pub async fn find_folder_password(
        &self,
        vault_id: &VaultId,
    ) -> Result<AccessKey> {
        let keeper = self.keeper.read().await;
        let urn = Vault::vault_urn(vault_id)?;
        let index_reader = self.index.read().await;
        let document = index_reader
            .find_by_urn(keeper.id(), &urn)
            .ok_or_else(|| Error::NoVaultEntry(urn.to_string()))?;

        let (_, secret, _) = keeper
            .read(document.id())
            .await?
            .ok_or_else(|| Error::NoVaultEntry(document.id().to_string()))?;

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

    /// Find the password used for symmetric file encryption (AGE).
    pub(crate) async fn find_file_encryption_password(
        &self,
    ) -> Result<SecretString> {
        let keeper = self.keeper.read().await;

        let reader = self.index.read().await;
        let urn: Urn = FILE_PASSWORD_URN.parse()?;
        let document = reader
            .find_by_urn(keeper.id(), &urn)
            .ok_or_else(|| Error::NoVaultEntry(urn.to_string()))?;
        let password =
            if let Some((_, Secret::Password { password, .. }, _)) =
                keeper.read(document.id()).await?
            {
                password
            } else {
                return Err(Error::VaultEntryKind(urn.to_string()));
            };
        Ok(password)
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use secrecy::{ExposeSecret, SecretString};
    use std::path::PathBuf;
    use tempfile::NamedTempFile;
    use urn::Urn;

    use crate::{
        account::{AuthenticatedUser, UserPaths},
        constants::LOGIN_SIGNING_KEY_URN,
        encode,
        passwd::diceware::generate_passphrase,
        vault::{
            secret::{Secret, SecretId, SecretMeta},
            Gatekeeper, Vault, VaultBuilder, VaultFlags,
        },
        vfs, Error,
    };

    #[tokio::test]
    async fn identity_not_identity_vault() -> Result<()> {
        let (password, _) = generate_passphrase()?;
        let vault =
            VaultBuilder::new().password(password.clone(), None).await?;
        let buffer = encode(&vault).await?;

        let mut identity = AuthenticatedUser::new(UserPaths::new_global(
            UserPaths::data_dir()?,
        ));
        let result = identity.login_buffer(buffer, password).await;
        if let Err(Error::NotIdentityVault) = result {
            Ok(())
        } else {
            panic!("expecting identity vault error");
        }
    }

    #[tokio::test]
    async fn identity_no_identity_signer() -> Result<()> {
        let (password, _) = generate_passphrase()?;

        let vault = VaultBuilder::new()
            .flags(VaultFlags::IDENTITY)
            .password(password.clone(), None)
            .await?;

        let buffer = encode(&vault).await?;

        let mut identity = AuthenticatedUser::new(UserPaths::new_global(
            UserPaths::data_dir()?,
        ));
        let result = identity.login_buffer(buffer, password).await;
        if let Err(Error::NoSecretUrn(_, _)) = result {
            Ok(())
        } else {
            panic!("expecting no identity signer error");
        }
    }

    #[tokio::test]
    async fn identity_signer_kind() -> Result<()> {
        let (password, _) = generate_passphrase()?;

        let vault = VaultBuilder::new()
            .flags(VaultFlags::IDENTITY)
            .password(password.clone(), None)
            .await?;

        let mut keeper = Gatekeeper::new(vault);
        keeper.unlock(password.clone().into()).await?;

        // Create a secret using the expected name but of the wrong kind
        let signer_secret = Secret::Note {
            text: SecretString::new("Mock note".to_owned()),
            user_data: Default::default(),
        };

        let urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
        let mut signer_meta =
            SecretMeta::new(urn.as_str().to_owned(), signer_secret.kind());
        signer_meta.set_urn(Some(urn));
        keeper
            .create(SecretId::new_v4(), signer_meta, signer_secret)
            .await?;

        let vault: Vault = keeper.into();
        let buffer = encode(&vault).await?;

        let mut identity = AuthenticatedUser::new(UserPaths::new_global(
            UserPaths::data_dir()?,
        ));
        let result = identity.login_buffer(buffer, password).await;
        if let Err(Error::WrongSecretKind(_, _)) = result {
            Ok(())
        } else {
            panic!("expecting identity signer kind error");
        }
    }
}
