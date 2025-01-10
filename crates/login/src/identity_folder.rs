//! Login identity vault management.
//!
//! Provides access to an identity vault containing
//! the account signing key and delegated passwords used
//! for folders managed by an account.
//!
//! This enables user interfaces to protect both the signing
//! key and folder passwords using a single primary password.
use crate::device::{DeviceManager, DeviceSigner};
use crate::{Error, PrivateIdentity, Result, UrnLookup};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use sos_backend::Folder;
use sos_backend::VaultWriter;
use sos_backend::{AccessPoint, FolderEventLog};
use sos_core::{
    constants::LOGIN_AGE_KEY_URN,
    crypto::{AccessKey, KeyDerivation},
    decode, encode, AccountId, Paths,
};
use sos_filesystem::FileSystemAccessPoint;
use sos_password::diceware::generate_passphrase_words;
use sos_signer::ed25519;
use sos_vault::{
    secret::{Secret, SecretId, SecretMeta, SecretRow, SecretSigner},
    BuilderCredentials, SecretAccess, Vault, VaultBuilder, VaultFlags,
    VaultId,
};
use sos_vfs as vfs;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;
use urn::Urn;

/// Number of words to use when generating passphrases for vaults.
const VAULT_PASSPHRASE_WORDS: usize = 12;

/// Identity folder that reads and writes to disc.
pub type DiscIdentityFolder = IdentityFolder;

/// Identity vault stores the account signing key,
/// asymmetric encryption key and delegated passwords.
pub struct IdentityFolder {
    /// Folder storage.
    #[doc(hidden)]
    pub folder: Folder,
    /// Lookup table.
    #[doc(hidden)]
    pub index: UrnLookup,

    private_identity: PrivateIdentity,
    pub(super) devices: Option<crate::device::DeviceManager>,
}

impl IdentityFolder {
    /// Private identity.
    pub fn private_identity(&self) -> &PrivateIdentity {
        &self.private_identity
    }

    /// Account address.
    pub fn account_id(&self) -> &AccountId {
        self.private_identity.account_id()
    }

    /// Get the vault.
    pub fn vault(&self) -> &Vault {
        self.folder.keeper().vault()
    }

    /// Get the access point.
    pub fn keeper(&self) -> &AccessPoint {
        self.folder.keeper()
    }

    /// Get the event log.
    pub fn event_log(&self) -> Arc<RwLock<FolderEventLog>> {
        self.folder.event_log()
    }

    /// Verify the access key for this account.
    pub async fn verify(&self, key: &AccessKey) -> bool {
        self.folder.keeper().verify(key).await.ok().is_some()
    }

    /// Signing key for this device.
    ///
    /// # Panics
    ///
    /// If the device manager has not been initialized.
    pub fn device(&self) -> &DeviceSigner {
        self.devices.as_ref().unwrap().signer()
    }

    /// Device manager.
    pub fn devices(&self) -> Result<&DeviceManager> {
        self.devices.as_ref().ok_or(Error::NotAuthenticated)
    }

    /// Rename this identity vault.
    pub async fn rename(&mut self, account_name: String) -> Result<()> {
        self.folder
            .keeper_mut()
            .set_vault_name(account_name.clone())
            .await?;
        Ok(())
    }

    /// Ensure that the account has a vault for storing device specific
    /// information such as the private key used to identify a machine.
    pub(super) async fn ensure_device_vault(
        &mut self,
        paths: &Paths,
    ) -> Result<()> {
        let device_vault = if vfs::try_exists(paths.device_file()).await? {
            let buffer = vfs::read(paths.device_file()).await?;
            let vault: Vault = decode(&buffer).await?;
            Some(vault)
        } else {
            None
        };

        let device_manager = if let Some(vault) = device_vault {
            self.read_device_vault(paths, vault).await
        } else {
            self.create_device_vault(paths, DeviceSigner::new_random(), true)
                .await
        };

        self.devices = Some(device_manager?);

        Ok(())
    }

    fn device_urn(&self) -> Result<Urn> {
        use sos_core::constants::DEVICE_KEY_URN;
        Ok(DEVICE_KEY_URN.parse()?)
    }

    async fn read_device_vault(
        &mut self,
        paths: &Paths,
        vault: Vault,
    ) -> Result<DeviceManager> {
        let device_key_urn = self.device_urn()?;
        let device_vault_path = paths.device_file().to_owned();

        tracing::debug!(urn = %device_key_urn, "read_device_vault");

        let summary = vault.summary().clone();
        let device_password = self
            .find_folder_password(summary.id())
            .await?
            .ok_or(Error::NoFolderPassword(*summary.id()))?;

        let mirror = VaultWriter::new_fs(&device_vault_path).await?;
        let mut device_keeper =
            FileSystemAccessPoint::new_mirror(vault, Box::new(mirror));
        let key: AccessKey = device_password.into();
        device_keeper.unlock(&key).await?;

        let mut device_signer_secret: Option<Secret> = None;
        for id in device_keeper.vault().keys() {
            if let Some((meta, secret, _)) =
                device_keeper.read_secret(id).await?
            {
                if let Some(urn) = meta.urn() {
                    if urn == &device_key_urn {
                        device_signer_secret = Some(secret);
                    }
                    // Add to the URN lookup index
                    self.index
                        .insert((*device_keeper.id(), urn.clone()), *id);
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
            Ok(DeviceManager::new(
                key.into(),
                AccessPoint::FileSystem(device_keeper),
            ))
        } else {
            Err(Error::VaultEntryKind(device_key_urn.to_string()))
        }
    }

    #[doc(hidden)]
    pub async fn create_device_vault(
        &mut self,
        paths: &Paths,
        signer: DeviceSigner,
        mirror: bool,
    ) -> Result<DeviceManager> {
        let device_vault_path = paths.device_file().to_owned();
        // Prepare the password for the device vault
        let device_password = self.generate_folder_password()?;

        // Prepare the device vault
        let vault = VaultBuilder::new()
            .public_name("Device".to_string())
            .flags(
                VaultFlags::SYSTEM | VaultFlags::DEVICE | VaultFlags::NO_SYNC,
            )
            .build(BuilderCredentials::Password(
                device_password.clone().into(),
                None,
            ))
            .await?;

        let device_key_urn = self.device_urn()?;

        tracing::debug!(urn = %device_key_urn, mirror = %mirror, "create_device_vault");

        self.save_folder_password(vault.id(), device_password.clone().into())
            .await?;

        let key: AccessKey = device_password.into();
        let mut device_keeper = if mirror {
            let buffer = encode(&vault).await?;
            vfs::write_exclusive(&device_vault_path, &buffer).await?;
            let mirror = VaultWriter::new_fs(&device_vault_path).await?;
            FileSystemAccessPoint::new_mirror(vault, Box::new(mirror))
        } else {
            FileSystemAccessPoint::new(vault)
        };
        device_keeper.unlock(&key).await?;

        let secret = Secret::Signer {
            private_key: SecretSigner::SinglePartyEd25519(SecretBox::new(
                signer.signing_key().to_bytes().into(),
            )),
            user_data: Default::default(),
        };
        let mut meta =
            SecretMeta::new("Device Key".to_string(), secret.kind());
        meta.set_urn(Some(device_key_urn.clone()));

        let id = SecretId::new_v4();
        let secret_data = SecretRow::new(id, meta, secret);
        device_keeper.create_secret(&secret_data).await?;

        {
            self.index.insert((*device_keeper.id(), device_key_urn), id);
        }

        Ok(DeviceManager::new(
            signer,
            AccessPoint::FileSystem(device_keeper),
        ))
    }

    /// Generate a folder password.
    pub(crate) fn generate_folder_password(&self) -> Result<SecretString> {
        let (vault_passphrase, _) =
            generate_passphrase_words(VAULT_PASSPHRASE_WORDS)?;
        Ok(vault_passphrase)
    }

    /// Save a folder password into this identity.
    pub(crate) async fn save_folder_password(
        &mut self,
        vault_id: &VaultId,
        key: AccessKey,
    ) -> Result<()> {
        let urn = Vault::vault_urn(vault_id)?;
        tracing::debug!(folder = %vault_id, urn = %urn, "save_folder_password");

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
        self.folder.create_secret(&secret_data).await?;

        self.index.insert((*self.folder.id(), urn), id);

        Ok(())
    }

    /// Find a folder password in this identity.
    ///
    /// The identity vault must already be unlocked to extract
    /// the secret password.
    #[doc(hidden)]
    pub async fn find_folder_password(
        &self,
        vault_id: &VaultId,
    ) -> Result<Option<AccessKey>> {
        let urn = Vault::vault_urn(vault_id)?;

        tracing::debug!(
            folder = %vault_id,
            urn = %urn,
            "find_folder_password");

        if let Some(id) = self.index.get(&(*self.folder.id(), urn.clone())) {
            let (_, secret, _) =
                self.folder.read_secret(id).await?.ok_or_else(|| {
                    Error::NoSecretId(*self.folder.id(), *id)
                })?;

            let key = match secret {
                Secret::Password { password, .. } => {
                    AccessKey::Password(password)
                }
                Secret::Age { key, .. } => {
                    AccessKey::Identity(key.expose_secret().parse().map_err(
                        |s: &str| Error::InvalidX25519Identity(s.to_owned()),
                    )?)
                }
                _ => {
                    return Err(Error::VaultEntryKind(urn.to_string()));
                }
            };
            Ok(Some(key))
        } else {
            Ok(None)
        }
    }

    /// Remove a folder password from this identity.
    pub(crate) async fn remove_folder_password(
        &mut self,
        vault_id: &VaultId,
    ) -> Result<()> {
        tracing::debug!(folder = %vault_id, "remove folder password");

        let (keeper_id, id, urn) = {
            let urn = Vault::vault_urn(vault_id)?;
            let id = self
                .index
                .get(&(*self.folder.keeper().id(), urn.clone()))
                .ok_or(Error::NoFolderPassword(*vault_id))?;
            (*self.folder.keeper().id(), *id, urn)
        };

        self.folder.delete_secret(&id).await?;
        self.index.remove(&(keeper_id, urn));

        Ok(())
    }

    /// Rebuild the index lookup for folder passwords.
    pub async fn rebuild_lookup_index(&mut self) -> Result<()> {
        let keeper = self.keeper();
        let (index, _) = Self::lookup_identity_secrets(keeper).await?;
        self.index = index;
        Ok(())
    }

    #[cfg(feature = "files")]
    pub(crate) async fn create_file_encryption_password(
        &mut self,
    ) -> Result<()> {
        use sos_core::constants::FILE_PASSWORD_URN;
        use sos_vault::secret::UserData;
        let file_passphrase = self.generate_folder_password()?;
        let secret = Secret::Password {
            password: file_passphrase,
            name: None,
            user_data: UserData::new_comment(self.account_id().to_string()),
        };
        let mut meta =
            SecretMeta::new("File Encryption".to_string(), secret.kind());
        let urn: Urn = FILE_PASSWORD_URN.parse()?;
        meta.set_urn(Some(urn.clone()));

        let secret_id = SecretId::new_v4();
        let secret_data = SecretRow::new(secret_id, meta, secret);
        self.folder.create_secret(&secret_data).await?;
        self.index.insert((*self.folder.id(), urn), secret_id);

        Ok(())
    }

    /// Find the password used for symmetric file encryption (AGE).
    #[cfg(feature = "files")]
    pub(crate) async fn find_file_encryption_password(
        &self,
    ) -> Result<SecretString> {
        use sos_core::constants::FILE_PASSWORD_URN;
        let urn: Urn = FILE_PASSWORD_URN.parse()?;

        let id = self
            .index
            .get(&(*self.folder.id(), urn.clone()))
            .ok_or_else(|| Error::NoFileEncryptionPassword)?;

        let password =
            if let Some((_, Secret::Password { password, .. }, _)) =
                self.folder.read_secret(id).await?
            {
                password
            } else {
                return Err(Error::VaultEntryKind(urn.to_string()));
            };
        Ok(password)
    }

    /// Sign out the identity vault.
    ///
    /// Locks the identity vault and device vault.
    pub async fn sign_out(&mut self) -> Result<()> {
        // Lock the identity vault
        self.folder.lock();
        self.index = Default::default();

        // Lock the devices vault
        if let Some(devices) = self.devices.as_mut() {
            devices.sign_out();
        }

        Ok(())
    }

    /// Lookup secrets in the identity folder and prepare
    /// the URN lookup index which maps URNs to the
    /// corresponding secret identifiers.
    async fn lookup_identity_secrets(
        keeper: &AccessPoint,
    ) -> Result<(UrnLookup, Option<Secret>)> {
        let mut index: UrnLookup = Default::default();

        // let signer_urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
        let identity_urn: Urn = LOGIN_AGE_KEY_URN.parse()?;

        // let mut signer_secret: Option<Secret> = None;
        let mut identity_secret: Option<Secret> = None;

        for secret_id in keeper.vault().keys() {
            if let Some((meta, secret, _)) =
                keeper.read_secret(secret_id).await?
            {
                if let Some(urn) = meta.urn() {
                    if urn == &identity_urn {
                        identity_secret = Some(secret);
                    }

                    // Add to the URN lookup index
                    index.insert((*keeper.id(), urn.clone()), *secret_id);
                }
            }
        }
        Ok((index, identity_secret))
    }

    async fn login_private_identity(
        account_id: AccountId,
        keeper: &AccessPoint,
    ) -> Result<(UrnLookup, PrivateIdentity)> {
        let (index, identity_secret) =
            Self::lookup_identity_secrets(keeper).await?;

        let identity = identity_secret.ok_or(Error::NoIdentityKey)?;

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
            account_id,
            shared_public: shared.to_public(),
            shared_private: shared,
        };

        Ok((index, private_identity))
    }

    /// Identifier of the folder.
    pub fn folder_id(&self) -> &VaultId {
        self.folder.id()
    }
}

impl From<IdentityFolder> for Vault {
    fn from(value: IdentityFolder) -> Self {
        value.folder.into()
    }
}

impl IdentityFolder {
    /// Create a new identity folder with a primary password.
    ///
    /// Generates a new random single party signing key and
    /// a public identity key for asymmetric encryption and
    /// stores them in the identity vault.
    pub async fn new(
        name: String,
        password: SecretString,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let account_id = AccountId::random();
        tracing::debug!(account_id = %account_id, "new_identity_folder");

        let data_dir = if let Some(data_dir) = &data_dir {
            data_dir.clone()
        } else {
            Paths::data_dir()?
        };
        let paths = Paths::new(data_dir, account_id.to_string());

        let vault = VaultBuilder::new()
            .public_name(name)
            .flags(VaultFlags::IDENTITY)
            .build(BuilderCredentials::Password(
                password.clone(),
                Some(KeyDerivation::generate_seed()),
            ))
            .await?;

        let buffer = encode(&vault).await?;
        vfs::write_exclusive(paths.identity_vault(), buffer).await?;

        let mut folder =
            Folder::new_file_system(paths.identity_vault()).await?;
        let key: AccessKey = password.into();
        folder.unlock(&key).await?;

        /*
        // Store the signing key
        let private_key = SecretSigner::SinglePartyEcdsa(SecretBox::new(
            signer.to_bytes().into(),
        ));
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
        folder.create_secret(&secret_data).await?;
        */

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
        folder.create_secret(&secret_data).await?;

        let private_identity = PrivateIdentity {
            account_id,
            shared_public: shared.to_public(),
            shared_private: shared,
        };

        let mut index: UrnLookup = Default::default();
        index.insert((*folder.id(), identity_urn), identity_id);

        Ok(Self {
            folder,
            index,
            private_identity,
            devices: None,
        })
    }

    /// Login to an identity vault.
    pub async fn login(
        account_id: &AccountId,
        path: impl AsRef<Path>,
        key: &AccessKey,
    ) -> Result<Self> {
        let mut folder = Folder::new_file_system(path).await?;

        if !folder
            .keeper()
            .vault()
            .flags()
            .contains(VaultFlags::IDENTITY)
        {
            return Err(Error::NotIdentityFolder);
        }

        folder.unlock(key).await?;

        let (index, private_identity) =
            Self::login_private_identity(*account_id, folder.keeper())
                .await?;

        Ok(Self {
            folder,
            index,
            private_identity,
            devices: None,
        })
    }
}
