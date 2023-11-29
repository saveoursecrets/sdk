//! Login identity vault.
//!
//! Identity provides access to a login vault containing
//! the account signing key and delegated passwords used
//! for folders managed by the account.
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
    account::{
        password::DelegatedPassword, search::SearchIndex, AccountInfo,
        AccountsList, UserPaths,
    },
    commit::CommitState,
    constants::{LOGIN_AGE_KEY_URN, LOGIN_SIGNING_KEY_URN, VAULT_EXT, DEVICE_KEY_URN},
    crypto::{AccessKey, KeyDerivation},
    encode, decode,
    events::{AuditEvent, Event, EventKind},
    signer::{
        ecdsa::{BoxedEcdsaSigner, SingleParty},
        ed25519,
        Signer,
    },
    vault::{
        secret::{Secret, SecretMeta, SecretSigner},
        Gatekeeper, Vault, VaultBuilder, VaultFlags, VaultId,
        VaultAccess, VaultWriter,
    },
    vfs, Error, Result,
};

use tracing::{span, Level};

#[cfg(feature = "device")]
use crate::account::DeviceSigner;

/// Number of words to use when generating passphrases for vaults.
const VAULT_PASSPHRASE_WORDS: usize = 12;

/// Authenticated user information.
pub struct AuthenticatedUser {
    account: AccountInfo,
    identity: UserIdentity,
    #[cfg(feature = "device")]
    device: DeviceSigner,
}

impl AuthenticatedUser {
    /// Account information.
    pub fn account(&self) -> &AccountInfo {
        &self.account
    }

    /// User identity reference.
    pub fn identity(&self) -> &UserIdentity {
        &self.identity
    }

    /// The device signing key.
    #[cfg(feature = "device")]
    pub fn device(&self) -> &DeviceSigner {
        &self.device
    }

    /// Verify the passphrase for this account.
    pub async fn verify(&self, key: &AccessKey) -> bool {
        let keeper = self.identity().keeper();
        let reader = keeper.read().await;
        let result = reader.verify(key).await.ok();
        result.is_some()
    }

    /// Delete the account for this user.
    ///
    /// Moves the account identity vault and data directory to the
    /// trash directory.
    pub async fn delete_account(&self, paths: &UserPaths) -> Result<Event> {
        vfs::remove_file(paths.identity_vault()).await?;
        vfs::remove_dir_all(paths.user_dir()).await?;

        let event = Event::CreateAccount(AuditEvent::new(
            EventKind::DeleteAccount,
            self.identity.address().clone(),
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
            let keeper = self.identity.keeper();
            let mut writer = keeper.write().await;
            writer.vault_mut().set_name(account_name.clone());
        }

        // Update vault file on disc
        let identity_vault_file = paths.identity_vault();

        let vault_file = VaultWriter::open(&identity_vault_file).await?;
        let mut access = VaultWriter::new(identity_vault_file, vault_file)?;
        access.set_vault_name(account_name.clone()).await?;

        // Update in-memory account information
        self.account.set_label(account_name);

        Ok(())
    }
    
    /*
    /// Generate a folder password.
    pub fn generate_folder_password() -> Result<SecretString> {
        let (vault_passphrase, _) =
            generate_passphrase_words(VAULT_PASSPHRASE_WORDS)?;
        Ok(vault_passphrase)
    }
    */

    /// Save a folder password into an identity vault.
    pub async fn save_folder_password(
        &self,
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

        //let mut writer = self.identity.index.write().await;
        //writer.prepare(&vault_id, &id, &meta, &secret);

        let mut keeper = self.identity.keeper.write().await;
        let (id, _) = keeper.create(meta, secret).await?;

        todo!("add to the search index...");

        Ok(())
    }

    /// Remove a folder password from an identity vault.
    pub async fn remove_folder_password(
        &self,
        vault_id: &VaultId,
    ) -> Result<()> {

        let id = {
            let keeper = self.identity.keeper.write().await;
            let urn = Vault::vault_urn(vault_id)?;
            let index_reader = self.identity.index.read().await;
            let document = index_reader
                .find_by_urn(keeper.id(), &urn)
                .ok_or(Error::NoVaultEntry(urn.to_string()))?;

            *document.id()
        };

        let mut keeper = self.identity.keeper.write().await;
        keeper.delete(&id).await?;

        todo!("remove from the search index");

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
        let keeper = self.identity.keeper.read().await;
        let urn = Vault::vault_urn(vault_id)?;
        let index_reader = self.identity.index.read().await;
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
        identity: Arc<RwLock<Gatekeeper>>,
    ) -> Result<SecretString> {
        let keeper = identity.read().await;

        /*
        let index = keeper.index();
        let reader = index.read().await;
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
        */

        todo!();
    }


    /// Sign out this user by locking the account identity vault.
    pub async fn sign_out(&mut self) {
        tracing::debug!("identity vault sign out");
        let keeper = self.identity.keeper();
        let mut writer = keeper.write().await;
        writer.lock();
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

/// User identity containing the account signing keys.
///
/// Exposes access to the identity vault for access to
/// delegated passwords.
pub struct UserIdentity {
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
}

impl UserIdentity {
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
}

/// Provides access to the identity vault used for account authentication.
///
/// A login vault is the master vault for an account. It stores the
/// signing keys for the account and delegated passphrases for folders
/// managed by the account.
pub struct Identity {
    index: Arc<RwLock<SearchIndex>>,
}

impl Identity {
    /// Create a new identity.
    pub fn new() -> Self {
        Self {
            index: Arc::new(RwLock::new(SearchIndex::new())),
        }
    }

    /// Create a new login vault with a master passphrase.
    ///
    /// Generates a new random single party signing key and
    /// stores it in the new vault along with an encryption
    /// passphrase to use for vaults accessed by this identity.
    pub async fn new_login_vault(
        name: String,
        master_passphrase: SecretString,
    ) -> Result<(Address, Vault)> {
        let vault = VaultBuilder::new()
            .public_name(name)
            .flags(VaultFlags::IDENTITY)
            .password(
                master_passphrase.clone(),
                Some(KeyDerivation::generate_seed()),
            )
            .await?;

        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(master_passphrase.into()).await?;

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
        keeper.create(signer_meta, signer_secret).await?;

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
        keeper.create(age_meta, age_secret).await?;

        Ok((address, keeper.into()))
    }

    /// Attempt to login using a file path.
    pub(crate) async fn login_file<P: AsRef<Path>>(
        &self,
        file: P,
        master_passphrase: SecretString,
        //search_index: Option<Arc<RwLock<SearchIndex>>>,
    ) -> Result<UserIdentity> {
        let vault_file = VaultWriter::open(file.as_ref()).await?;
        let mirror = VaultWriter::new(file.as_ref(), vault_file)?;
        let buffer = vfs::read(file.as_ref()).await?;
        self.login_buffer(
            buffer,
            master_passphrase,
            //search_index,
            Some(mirror),
        )
        .await
    }

    /// Attempt to login using a buffer.
    pub(crate) async fn login_buffer<B: AsRef<[u8]>>(
        &self,
        buffer: B,
        master_passphrase: SecretString,
        //search_index: Option<Arc<RwLock<SearchIndex>>>,
        mirror: Option<VaultWriter<vfs::File>>,
    ) -> Result<UserIdentity> {
        let vault: Vault = decode(buffer.as_ref()).await?;
        
        if !vault.flags().contains(VaultFlags::IDENTITY) {
            return Err(Error::NotIdentityVault);
        }

        let mut keeper = if let Some(mirror) = mirror {
            Gatekeeper::new_mirror(vault, mirror, None)
        } else {
            Gatekeeper::new(vault, None)
        };

        keeper.unlock(master_passphrase.into()).await?;

        {
            let mut writer = self.index.write().await;
            writer.add_folder(&keeper).await?;
        }

        let reader = self.index.read().await;

        let urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
        let document = reader
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
        let document = reader
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

        drop(reader);

        Ok(UserIdentity {
            address,
            signer,
            shared_public: shared.to_public(),
            shared_private: shared,
            keeper: Arc::new(RwLock::new(keeper)),
            index: Arc::clone(&self.index),
        })
    }

    /// Sign in a user.
    pub async fn sign_in(
        &self,
        address: &Address,
        paths: &UserPaths,
        passphrase: SecretString,
        //index: Arc<RwLock<SearchIndex>>,
    ) -> Result<AuthenticatedUser> {
        let span = span!(Level::DEBUG, "login");
        let _enter = span.enter();

        let accounts = AccountsList::list_accounts(Some(paths)).await?;
        let account = accounts
            .into_iter()
            .find(|a| a.address() == address)
            .ok_or_else(|| Error::NoAccount(address.to_string()))?;

        let identity_path = paths.identity_vault();

        tracing::debug!(identity_path = ?identity_path);

        let mut identity =
            self.login_file(identity_path, passphrase)
                .await?;

        tracing::debug!("identity verified");

        println!("ENSURING DEVICE VAULT");
        
        // Lazily create or retrieve a device specific signing key
        #[cfg(feature = "device")]
        let device =
            Self::ensure_device_vault(address, paths, &mut identity).await?;

        println!("ENSURED!!!!");

        Ok(AuthenticatedUser {
            account,
            identity,
            #[cfg(feature = "device")]
            device,
        })
    }

    /// Ensure that the account has a vault for storing device specific
    /// information such as the private key used to identify a machine
    /// on a peer to peer network.
    #[cfg(feature = "device")]
    async fn ensure_device_vault(
        _address: &Address,
        paths: &UserPaths,
        user: &mut UserIdentity,
    ) -> Result<DeviceSigner> {
        let local_accounts = AccountsList::new(paths);

        let vaults = local_accounts.list_local_vaults(true).await?;
        let device_vault = vaults.into_iter().find_map(|(summary, _)| {
            if summary.flags().is_system() && summary.flags().is_device() {
                Some(summary)
            } else {
                None
            }
        });

        let urn: Urn = DEVICE_KEY_URN.parse()?;

        let index = user.index();

        if let Some(summary) = device_vault {
            let device_passphrase = DelegatedPassword::find_folder_password(
                user.keeper(),
                //user.index(),
                summary.id(),
            )
            .await?;

            let (vault, _) =
                local_accounts.find_local_vault(summary.id(), true).await?;
            let search_index = user.index();
            let mut device_keeper = Gatekeeper::new(vault, None);
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
            let device_passphrase =
                DelegatedPassword::generate_folder_password()?;

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

            DelegatedPassword::save_folder_password(
                user.keeper(),
                vault.id(),
                device_passphrase.clone().into(),
            )
            .await?;

            let mut device_keeper = Gatekeeper::new(vault, None);
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
            device_keeper.create(meta, secret).await?;

            let device_vault: Vault = device_keeper.into();
            let summary = device_vault.summary().clone();

            let buffer = encode(&device_vault).await?;
            let vaults_dir = paths.vaults_dir();
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

}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use secrecy::{ExposeSecret, SecretString};
    use tempfile::NamedTempFile;
    use urn::Urn;

    use super::Identity;

    use crate::{
        constants::LOGIN_SIGNING_KEY_URN,
        encode,
        passwd::diceware::generate_passphrase,
        vault::{
            secret::{Secret, SecretMeta},
            Gatekeeper, Vault, VaultBuilder, VaultFlags,
        },
        vfs, Error,
    };

    //use crate::test_utils::*;

    #[tokio::test]
    async fn identity_create_login() -> Result<()> {
        let (master_passphrase, _) = generate_passphrase()?;
        let auth_master_passphrase =
            SecretString::new(master_passphrase.expose_secret().to_owned());
        let (_address, vault) =
            Identity::new_login_vault("Login".to_owned(), master_passphrase)
                .await?;
        let buffer = encode(&vault).await?;
        let temp = NamedTempFile::new()?;
        vfs::write(temp.path(), buffer).await?;

        let identity = Identity::new();
        let _ =
            identity.login_file(temp.path(), auth_master_passphrase)
                .await?;
        Ok(())
    }

    #[tokio::test]
    async fn identity_not_identity_vault() -> Result<()> {
        let (master_passphrase, _) = generate_passphrase()?;
        let vault = VaultBuilder::new()
            .password(master_passphrase.clone(), None)
            .await?;
        let buffer = encode(&vault).await?;

        let identity = Identity::new();
        let result =
            identity.login_buffer(buffer, master_passphrase, None)
                .await;
        if let Err(Error::NotIdentityVault) = result {
            Ok(())
        } else {
            panic!("expecting identity vault error");
        }
    }

    #[tokio::test]
    async fn identity_no_identity_signer() -> Result<()> {
        let (master_passphrase, _) = generate_passphrase()?;

        let vault = VaultBuilder::new()
            .flags(VaultFlags::IDENTITY)
            .password(master_passphrase.clone(), None)
            .await?;

        let buffer = encode(&vault).await?;

        let identity = Identity::new();
        let result =
            identity.login_buffer(buffer, master_passphrase, None)
                .await;
        if let Err(Error::NoSecretUrn(_, _)) = result {
            Ok(())
        } else {
            panic!("expecting no identity signer error");
        }
    }

    #[tokio::test]
    async fn identity_signer_kind() -> Result<()> {
        let (master_passphrase, _) = generate_passphrase()?;

        let vault = VaultBuilder::new()
            .flags(VaultFlags::IDENTITY)
            .password(master_passphrase.clone(), None)
            .await?;

        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(master_passphrase.clone().into()).await?;

        // Create a secret using the expected name but of the wrong kind
        let signer_secret = Secret::Note {
            text: SecretString::new("Mock note".to_owned()),
            user_data: Default::default(),
        };

        let urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
        let mut signer_meta =
            SecretMeta::new(urn.as_str().to_owned(), signer_secret.kind());
        signer_meta.set_urn(Some(urn));
        keeper.create(signer_meta, signer_secret).await?;

        let vault: Vault = keeper.into();
        let buffer = encode(&vault).await?;
        
        let identity = Identity::new();
        let result =
            identity.login_buffer(buffer, master_passphrase, None)
                .await;
        if let Err(Error::WrongSecretKind(_, _)) = result {
            Ok(())
        } else {
            panic!("expecting identity signer kind error");
        }
    }
}
