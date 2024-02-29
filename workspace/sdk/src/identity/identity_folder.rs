//! Login identity vault management.
//!
//! Provides access to an identity vault containing
//! the account signing key and delegated passwords used
//! for folders managed by an account.
//!
//! This enables user interfaces to protect both the signing
//! key and folder passwords using a single primary password.
use crate::{
    constants::{
        FILE_PASSWORD_URN, LOGIN_AGE_KEY_URN, LOGIN_SIGNING_KEY_URN,
        VAULT_NSS,
    },
    crypto::{AccessKey, KeyDerivation},
    decode, encode,
    events::{
        DiscData, DiscLog, EventLogExt, FolderEventLog, MemoryData,
        MemoryFolderLog, MemoryLog, WriteEvent,
    },
    identity::{PrivateIdentity, UrnLookup},
    passwd::diceware::generate_passphrase_words,
    signer::{
        ecdsa::{Address, BoxedEcdsaSigner, SingleParty},
        ed25519, Signer,
    },
    storage::{DiscFolder, Folder, MemoryFolder},
    vault::{
        secret::{
            Secret, SecretId, SecretMeta, SecretRow, SecretSigner, UserData,
        },
        Gatekeeper, Vault, VaultBuilder, VaultFlags, VaultId, VaultWriter,
    },
    vfs, Error, Paths, Result,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{span, Level};
use urn::Urn;

#[cfg(feature = "device")]
use crate::device::{DeviceManager, DeviceSigner};

#[cfg(feature = "sync")]
use crate::sync::{CheckedPatch, FolderDiff, FolderMergeOptions};

/// Number of words to use when generating passphrases for vaults.
const VAULT_PASSPHRASE_WORDS: usize = 12;

/// Identity folder that reads and writes to disc.
pub type DiscIdentityFolder =
    IdentityFolder<FolderEventLog, DiscLog, DiscLog, DiscData>;

/// Identity folder that reads and writes to memory.
pub type MemoryIdentityFolder =
    IdentityFolder<MemoryFolderLog, MemoryLog, MemoryLog, MemoryData>;

/// Identity vault stores the account signing key,
/// asymmetric encryption key and delegated passwords.
pub struct IdentityFolder<T, R, W, D>
where
    T: EventLogExt<WriteEvent, R, W, D> + Send + Sync + 'static,
    R: AsyncRead + AsyncSeek + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    D: Clone + Send + Sync,
{
    folder: Folder<T, R, W, D>,
    pub(crate) index: UrnLookup,
    private_identity: PrivateIdentity,
    #[cfg(feature = "device")]
    pub(super) devices: Option<crate::device::DeviceManager>,
}

impl<T, R, W, D> IdentityFolder<T, R, W, D>
where
    T: EventLogExt<WriteEvent, R, W, D> + Send + Sync + 'static,
    R: AsyncRead + AsyncSeek + Unpin + Send + Sync + 'static,
    W: AsyncWrite + Unpin + Send + Sync + 'static,
    D: Clone + Send + Sync,
{
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

    /// Get the vault.
    pub fn vault(&self) -> &Vault {
        self.folder.keeper().vault()
    }

    /// Get the event log.
    pub fn event_log(&self) -> Arc<RwLock<T>> {
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
    #[cfg(feature = "device")]
    pub fn device(&self) -> &DeviceSigner {
        self.devices.as_ref().unwrap().signer()
    }

    /// Device manager.
    #[cfg(feature = "device")]
    pub fn devices(&self) -> Result<&DeviceManager> {
        self.devices.as_ref().ok_or(Error::NotAuthenticated)
    }

    /// Rename this identity vault.
    pub async fn rename(&mut self, account_name: String) -> Result<()> {
        self.folder
            .keeper
            .set_vault_name(account_name.clone())
            .await?;
        Ok(())
    }

    /// Ensure that the account has a vault for storing device specific
    /// information such as the private key used to identify a machine.
    #[cfg(feature = "device")]
    pub(super) async fn ensure_device_vault(
        &mut self,
        paths: &Paths,
    ) -> Result<()> {
        let device_vault_path = paths.device_file().to_owned();

        let device_vault = if vfs::try_exists(&device_vault_path).await? {
            let buffer = vfs::read(&device_vault_path).await?;
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

    #[cfg(feature = "device")]
    fn device_urn(&self) -> Result<Urn> {
        use crate::constants::DEVICE_KEY_URN;
        Ok(DEVICE_KEY_URN.parse()?)
    }

    #[cfg(feature = "device")]
    async fn read_device_vault(
        &mut self,
        paths: &Paths,
        vault: Vault,
    ) -> Result<DeviceManager> {
        let device_key_urn = self.device_urn()?;
        let device_vault_path = paths.device_file().to_owned();

        let summary = vault.summary().clone();
        let device_password = self.find_folder_password(summary.id()).await?;

        let vault_file = VaultWriter::open(&device_vault_path).await?;
        let mirror = VaultWriter::new(&device_vault_path, vault_file)?;

        let mut device_keeper = Gatekeeper::new_mirror(vault, mirror);
        let key: AccessKey = device_password.into();
        device_keeper.unlock(&key).await?;

        let mut device_signer_secret: Option<Secret> = None;
        {
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
    }

    #[doc(hidden)]
    #[cfg(feature = "device")]
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
                VaultFlags::SYSTEM
                    | VaultFlags::DEVICE
                    | VaultFlags::NO_SYNC_SELF
                    | VaultFlags::NO_SYNC_OTHER,
            )
            .password(device_password.clone().into(), None)
            .await?;

        let device_key_urn = self.device_urn()?;

        self.save_folder_password(vault.id(), device_password.clone().into())
            .await?;

        let buffer = encode(&vault).await?;
        vfs::write(&device_vault_path, &buffer).await?;
        let vault_file = VaultWriter::open(&device_vault_path).await?;

        let key: AccessKey = device_password.into();
        let mut device_keeper = if mirror {
            let mirror = VaultWriter::new(&device_vault_path, vault_file)?;
            Gatekeeper::new_mirror(vault, mirror)
        } else {
            Gatekeeper::new(vault)
        };
        device_keeper.unlock(&key).await?;

        let secret = Secret::Signer {
            private_key: SecretSigner::SinglePartyEd25519(SecretVec::new(
                signer.signing_key().to_bytes(),
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

        Ok(DeviceManager::new(signer, device_keeper))
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
        self.folder.create_secret(&secret_data).await?;

        self.index.insert((*self.folder.id(), urn), id);

        Ok(())
    }

    /// Find a folder password in this identity.
    ///
    /// The identity vault must already be unlocked to extract
    /// the secret password.
    pub(crate) async fn find_folder_password(
        &self,
        vault_id: &VaultId,
    ) -> Result<AccessKey> {
        let span = span!(Level::DEBUG, "find_folder_password");
        let _enter = span.enter();

        let urn = Vault::vault_urn(vault_id)?;

        tracing::debug!(folder = %vault_id, urn = %urn);

        let id = self
            .index
            .get(&(*self.folder.id(), urn.clone()))
            .ok_or_else(|| Error::NoVaultEntry(urn.to_string()))?;

        let (_, secret, _) = self
            .folder
            .read_secret(id)
            .await?
            .ok_or_else(|| Error::NoSecretId(*self.folder.id(), *id))?;

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
        Ok(key)
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
                .ok_or(Error::NoVaultEntry(urn.to_string()))?;
            (*self.folder.keeper().id(), *id, urn)
        };

        self.folder.delete_secret(&id).await?;
        self.index.remove(&(keeper_id, urn));

        Ok(())
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
        self.folder.create_secret(&secret_data).await?;
        self.index.insert((*self.folder.id(), urn), secret_id);

        Ok(())
    }

    /// Find the password used for symmetric file encryption (AGE).
    pub(crate) async fn find_file_encryption_password(
        &self,
    ) -> Result<SecretString> {
        let urn: Urn = FILE_PASSWORD_URN.parse()?;

        let id = self
            .index
            .get(&(*self.folder.id(), urn.clone()))
            .ok_or_else(|| Error::NoVaultEntry(urn.to_string()))?;

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
        #[cfg(feature = "device")]
        if let Some(devices) = self.devices.as_mut() {
            devices.sign_out();
        }

        Ok(())
    }

    async fn login_private_identity(
        keeper: &Gatekeeper,
    ) -> Result<(UrnLookup, PrivateIdentity)> {
        let mut index: UrnLookup = Default::default();

        let signer_urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
        let identity_urn: Urn = LOGIN_AGE_KEY_URN.parse()?;

        let mut signer_secret: Option<Secret> = None;
        let mut identity_secret: Option<Secret> = None;
        let mut folder_secrets = HashMap::new();

        for id in keeper.vault().keys() {
            if let Some((meta, secret, _)) = keeper.read_secret(id).await? {
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

        Ok((index, private_identity))
    }

    #[cfg(feature = "sync")]
    pub(crate) async fn merge(
        &mut self,
        diff: &FolderDiff,
    ) -> Result<CheckedPatch> {
        let id = *self.folder.id();
        let index = &mut self.index;
        self.folder
            .merge(diff, FolderMergeOptions::Urn(id, index))
            .await
    }
}

impl From<IdentityFolder<FolderEventLog, DiscLog, DiscLog, DiscData>>
    for Vault
{
    fn from(
        value: IdentityFolder<FolderEventLog, DiscLog, DiscLog, DiscData>,
    ) -> Self {
        value.folder.keeper.into()
    }
}

impl IdentityFolder<FolderEventLog, DiscLog, DiscLog, DiscData> {
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
        let signer = SingleParty::new_random();
        let address = signer.address()?;

        let data_dir = if let Some(data_dir) = &data_dir {
            data_dir.clone()
        } else {
            Paths::data_dir()?
        };
        let paths = Paths::new(data_dir, address.to_string());

        let vault = VaultBuilder::new()
            .public_name(name)
            .flags(VaultFlags::IDENTITY)
            .password(password.clone(), Some(KeyDerivation::generate_seed()))
            .await?;

        let buffer = encode(&vault).await?;
        vfs::write(paths.identity_vault(), buffer).await?;

        let mut folder = DiscFolder::new(paths.identity_vault()).await?;
        let key: AccessKey = password.into();
        folder.unlock(&key).await?;

        // Store the signing key
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
        folder.create_secret(&secret_data).await?;

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
            address,
            signer: Box::new(signer),
            shared_public: shared.to_public(),
            shared_private: shared,
        };

        let mut index: UrnLookup = Default::default();
        index.insert((*folder.id(), signer_urn), signer_id);
        index.insert((*folder.id(), identity_urn), identity_id);

        Ok(Self {
            folder,
            index,
            private_identity,
            #[cfg(feature = "device")]
            devices: None,
        })
    }

    /// Login to an identity vault.
    pub async fn login(
        path: impl AsRef<Path>,
        key: &AccessKey,
    ) -> Result<Self> {
        let mut folder = DiscFolder::new(path).await?;

        if !folder
            .keeper()
            .vault()
            .flags()
            .contains(VaultFlags::IDENTITY)
        {
            return Err(Error::NotIdentityFolder);
        }

        folder.unlock(&key).await?;

        let (index, private_identity) =
            Self::login_private_identity(folder.keeper()).await?;

        Ok(Self {
            folder,
            index,
            private_identity,
            #[cfg(feature = "device")]
            devices: None,
        })
    }
}

impl IdentityFolder<MemoryFolderLog, MemoryLog, MemoryLog, MemoryData> {
    /// Attempt to login using a buffer.
    ///
    /// The purpose of buffer login is to verify that a user
    /// can access the identity folder stored in a backup archive.
    pub async fn login(
        buffer: impl AsRef<[u8]>,
        key: &AccessKey,
    ) -> Result<Self> {
        let mut folder = MemoryFolder::new(buffer).await?;

        if !folder
            .keeper()
            .vault()
            .flags()
            .contains(VaultFlags::IDENTITY)
        {
            return Err(Error::NotIdentityFolder);
        }

        folder.unlock(&key).await?;

        let (index, private_identity) =
            Self::login_private_identity(folder.keeper()).await?;

        Ok(Self {
            folder,
            index,
            private_identity,
            #[cfg(feature = "device")]
            devices: None,
        })
    }
}
