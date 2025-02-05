//! Login identity folder management.
//!
//! Provides access to an identity folder containing
//! delegated passwords used to decrypt folders managed
//! by an account.
use crate::device::{DeviceManager, DeviceSigner};
use crate::{Error, PrivateIdentity, Result, UrnLookup};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use sos_backend::{
    database::{
        async_sqlite::Client,
        entity::{
            AccountEntity, AccountRow, FolderEntity, FolderRecord, FolderRow,
            SecretRecord,
        },
    },
    write_exclusive, AccessPoint, Folder, FolderEventLog,
};
use sos_core::{
    constants::LOGIN_AGE_KEY_URN, crypto::AccessKey, decode, encode,
    AccountId, AuthenticationError, Paths,
};
use sos_password::diceware::generate_passphrase_words;
use sos_signer::ed25519;
use sos_vault::Summary;
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

    /// Folder summary.
    pub async fn summary(&self) -> Summary {
        let access_point = self.folder.access_point();
        let access_point = access_point.lock().await;
        access_point.vault().summary().clone()
    }

    /*

    /// Get the access point.
    pub fn keeper(&self) -> &AccessPoint {
        self.folder.keeper()
    }
    */

    /// Reference to the folder.
    pub fn folder(&self) -> &Folder {
        &self.folder
    }

    /// Get the event log.
    pub fn event_log(&self) -> Arc<RwLock<FolderEventLog>> {
        self.folder.event_log()
    }

    /// Verify the access key for this account.
    pub async fn verify(&self, key: &AccessKey) -> bool {
        let access_point = self.folder.access_point();
        let access_point = access_point.lock().await;
        access_point.verify(key).await.ok().is_some()
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
        Ok(self
            .devices
            .as_ref()
            .ok_or(AuthenticationError::NotAuthenticated)?)
    }

    /// Rename this identity vault.
    pub async fn rename(&mut self, account_name: String) -> Result<()> {
        let access_point = self.folder.access_point();
        let mut access_point = access_point.lock().await;
        access_point.set_vault_name(account_name).await?;
        Ok(())
    }

    /// Ensure that the account has a vault for storing device specific
    /// information such as the private key used to identify a machine.
    pub(super) async fn ensure_device_vault_fs(
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
            let folder_id = *vault.id();
            let device_keeper =
                AccessPoint::new_fs(vault, paths.device_file());
            self.read_device_manager(&folder_id, device_keeper).await?
        } else {
            self.new_device_manager_fs(DeviceSigner::new_random(), paths)
                .await?
        };
        self.devices = Some(device_manager);
        Ok(())
    }

    pub(super) async fn ensure_device_vault_db(
        &mut self,
        client: &Client,
    ) -> Result<()> {
        let account_id = *self.private_identity.account_id();
        let device_folder = client
            .conn_and_then(move |conn| {
                let account = AccountEntity::new(&conn);
                let folder = FolderEntity::new(&conn);
                let account_row = account.find_one(&account_id)?;
                let device_folder =
                    folder.find_device_folder(account_row.row_id)?;
                let secrets = if let Some(device_folder) = &device_folder {
                    Some(folder.load_secrets(device_folder.row_id)?)
                } else {
                    None
                };
                Ok::<_, sos_backend::database::Error>(
                    device_folder.zip(secrets),
                )
            })
            .await?;

        let device_manager = if let Some((folder, secret_rows)) =
            device_folder
        {
            let record = FolderRecord::from_row(folder).await?;
            let mut vault = record.into_vault()?;
            for row in secret_rows {
                let record = SecretRecord::from_row(row).await?;
                let SecretRecord {
                    secret_id, commit, ..
                } = record;
                vault.insert_entry(secret_id, commit);
            }

            let folder_id = *vault.id();
            let device_keeper =
                AccessPoint::new_db(vault, client.clone(), folder_id).await;
            self.read_device_manager(&folder_id, device_keeper).await?
        } else {
            self.new_device_manager_db(DeviceSigner::new_random(), client)
                .await?
        };
        self.devices = Some(device_manager);
        Ok(())
    }

    /// Create a new file system device manager.
    pub async fn new_device_manager_fs(
        &mut self,
        signer: DeviceSigner,
        paths: &Paths,
    ) -> Result<DeviceManager> {
        let (device_password, device_vault) =
            self.create_device_vault().await?;
        let folder_id = *device_vault.id();
        let buffer = encode(&device_vault).await?;
        write_exclusive(paths.device_file(), &buffer).await?;

        let device_keeper =
            AccessPoint::new_fs(device_vault, paths.device_file());

        self.create_device_manager(
            signer,
            &folder_id,
            device_password,
            device_keeper,
        )
        .await
    }

    /// Create a new database device manager.
    pub async fn new_device_manager_db(
        &mut self,
        signer: DeviceSigner,
        client: &Client,
    ) -> Result<DeviceManager> {
        let (device_password, device_vault) =
            self.create_device_vault().await?;
        let folder_id = *device_vault.id();

        let account_id = *self.private_identity.account_id();
        let folder_row = FolderRow::new_insert(&device_vault).await?;
        client
            .conn(move |conn| {
                let account = AccountEntity::new(&conn);
                let folder = FolderEntity::new(&conn);
                let account_row = account.find_one(&account_id)?;
                let folder_id =
                    folder.insert_folder(account_row.row_id, &folder_row)?;
                account.insert_device_folder(account_row.row_id, folder_id)
            })
            .await
            .map_err(sos_backend::database::Error::from)?;

        let device_keeper =
            AccessPoint::new_db(device_vault, client.clone(), folder_id)
                .await;

        self.create_device_manager(
            signer,
            &folder_id,
            device_password,
            device_keeper,
        )
        .await
    }

    fn device_urn(&self) -> Result<Urn> {
        use sos_core::constants::DEVICE_KEY_URN;
        Ok(DEVICE_KEY_URN.parse()?)
    }

    async fn read_device_manager(
        &mut self,
        folder_id: &VaultId,
        mut device_keeper: AccessPoint,
    ) -> Result<DeviceManager> {
        let device_key_urn = self.device_urn()?;

        tracing::debug!(
            urn = %device_key_urn,
            "read_device_vault");

        let device_password = self
            .find_folder_password(folder_id)
            .await?
            .ok_or(Error::NoFolderPassword(*folder_id))?;

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
            Ok(DeviceManager::new(key.into(), device_keeper))
        } else {
            Err(Error::VaultEntryKind(device_key_urn.to_string()))
        }
    }

    async fn create_device_vault(&self) -> Result<(SecretString, Vault)> {
        // Prepare the password for the device vault
        let password = self.generate_folder_password()?;

        // Prepare the device vault
        let vault = VaultBuilder::new()
            .public_name("Device".to_string())
            .flags(
                VaultFlags::SYSTEM | VaultFlags::DEVICE | VaultFlags::NO_SYNC,
            )
            .build(BuilderCredentials::Password(
                password.clone().into(),
                None,
            ))
            .await?;

        Ok((password, vault))
    }

    async fn create_device_manager(
        &mut self,
        signer: DeviceSigner,
        folder_id: &VaultId,
        device_password: SecretString,
        mut device_keeper: AccessPoint,
    ) -> Result<DeviceManager> {
        let device_key_urn = self.device_urn()?;

        tracing::debug!(
            urn = %device_key_urn,
            "create_device_manager");

        self.save_folder_password(folder_id, device_password.clone().into())
            .await?;

        let key: AccessKey = device_password.into();
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
        let urn = Vault::vault_urn(vault_id)?;
        tracing::debug!(
            folder = %vault_id,
            urn = %urn,
            "save_folder_password",
        );

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

        self.index.insert((self.folder.id().await, urn), id);

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
        let folder_id = self.folder.id().await;

        tracing::debug!(
            folder = %vault_id,
            urn = %urn,
            "find_folder_password");

        if let Some(id) = self.index.get(&(folder_id, urn.clone())) {
            let (_, secret, _) = self
                .folder
                .read_secret(id)
                .await?
                .ok_or_else(|| Error::NoSecretId(folder_id, *id))?;

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
            let folder_id = self.folder.id().await;
            let urn = Vault::vault_urn(vault_id)?;
            let id = self
                .index
                .get(&(folder_id, urn.clone()))
                .ok_or(Error::NoFolderPassword(*vault_id))?;
            (folder_id, *id, urn)
        };

        self.folder.delete_secret(&id).await?;
        self.index.remove(&(keeper_id, urn));

        Ok(())
    }

    /// Rebuild the index lookup for folder passwords.
    pub async fn rebuild_lookup_index(&mut self) -> Result<()> {
        let access_point = self.folder.access_point();
        let access_point = access_point.lock().await;
        let (index, _) =
            Self::lookup_identity_secrets(&*access_point).await?;
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
        self.index.insert((self.folder.id().await, urn), secret_id);

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
            .get(&(self.folder.id().await, urn.clone()))
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
        self.folder.lock().await;
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
        println!("doing login private identity...");

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
    pub async fn folder_id(&self) -> VaultId {
        self.folder.id().await
    }

    /// Create an identity vault.
    async fn create_identity_vault(
        name: String,
        password: &SecretString,
    ) -> Result<Vault> {
        Ok(VaultBuilder::new()
            .public_name(name)
            .flags(VaultFlags::IDENTITY)
            .build(BuilderCredentials::Password(password.clone(), None))
            .await?)
    }

    async fn create_age_identity(
        account_id: &AccountId,
        folder: &mut Folder,
        index: &mut UrnLookup,
    ) -> Result<PrivateIdentity> {
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
            account_id: *account_id,
            shared_public: shared.to_public(),
            shared_private: shared,
        };

        index.insert((folder.id().await, identity_urn), identity_id);

        Ok(private_identity)
    }

    /// Create a new identity folder with a primary password on the file system.
    pub async fn new_fs(
        name: String,
        password: SecretString,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let account_id = AccountId::random();
        tracing::debug!(
            account_id = %account_id,
            "new_identity_folder::filesystem");

        let data_dir = if let Some(data_dir) = &data_dir {
            data_dir.clone()
        } else {
            Paths::data_dir()?
        };
        let paths = Paths::new(data_dir, account_id.to_string());

        let vault = Self::create_identity_vault(name, &password).await?;

        let buffer = encode(&vault).await?;
        write_exclusive(paths.identity_vault(), buffer).await?;

        let mut folder = Folder::new_fs(paths.identity_vault()).await?;
        let key: AccessKey = password.into();
        folder.unlock(&key).await?;

        let mut index: UrnLookup = Default::default();

        let private_identity =
            Self::create_age_identity(&account_id, &mut folder, &mut index)
                .await?;

        Ok(Self {
            folder,
            index,
            private_identity,
            devices: None,
        })
    }

    /// Create a new identity folder with a primary password in the database.
    pub async fn new_db(
        name: String,
        password: SecretString,
        client: &Client,
    ) -> Result<Self> {
        let account_id = AccountId::random();
        tracing::debug!(
            account_id = %account_id,
            "new_identity_folder::database");

        let vault =
            Self::create_identity_vault(name.clone(), &password).await?;

        let account_row = AccountRow::new_insert(&account_id, name)?;
        let folder_row = FolderRow::new_insert(&vault).await?;
        client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let account = AccountEntity::new(&tx);
                let folder = FolderEntity::new(&tx);

                let account_id = account.insert(&account_row)?;
                let folder_id =
                    folder.insert_folder(account_id, &folder_row)?;
                account.insert_login_folder(account_id, folder_id)?;

                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(sos_backend::database::Error::from)?;

        let mut folder =
            Folder::new_db(client.clone(), account_id, *vault.id()).await?;
        let key: AccessKey = password.into();
        folder.unlock(&key).await?;

        let mut index: UrnLookup = Default::default();

        let private_identity =
            Self::create_age_identity(&account_id, &mut folder, &mut index)
                .await?;

        Ok(Self {
            folder,
            index,
            private_identity,
            devices: None,
        })
    }

    /// Login to an identity folder.
    pub async fn login_fs(
        account_id: &AccountId,
        key: &AccessKey,
        path: impl AsRef<Path>,
    ) -> Result<Self> {
        let mut folder = Folder::new_fs(path).await?;

        {
            let access_point = folder.access_point();
            let access_point = access_point.lock().await;
            if !access_point.vault().flags().contains(VaultFlags::IDENTITY) {
                return Err(Error::NotIdentityFolder);
            }
        }

        folder.unlock(key).await?;

        let access_point = folder.access_point();
        let access_point = access_point.lock().await;
        let (index, private_identity) =
            Self::login_private_identity(*account_id, &*access_point).await?;

        Ok(Self {
            folder,
            index,
            private_identity,
            devices: None,
        })
    }

    /// Login to an identity folder.
    pub async fn login_db(
        account_id: &AccountId,
        key: &AccessKey,
        client: &Client,
    ) -> Result<Self> {
        let login_account_id = *account_id;
        let login_folder = client
            .conn(move |conn| {
                let account = AccountEntity::new(&conn);
                let folder = FolderEntity::new(&conn);
                let account_row = account.find_one(&login_account_id)?;
                Ok(folder.find_login_folder(account_row.row_id)?)
            })
            .await
            .map_err(sos_backend::database::Error::from)?;

        let login_folder = FolderRecord::from_row(login_folder).await?;
        let mut folder = Folder::new_db(
            client.clone(),
            *account_id,
            *login_folder.summary.id(),
        )
        .await?;

        {
            let access_point = folder.access_point();
            let access_point = access_point.lock().await;
            if !access_point.vault().flags().contains(VaultFlags::IDENTITY) {
                return Err(Error::NotIdentityFolder);
            }
        }

        folder.unlock(key).await?;

        let access_point = folder.access_point();
        let access_point = access_point.lock().await;
        let (index, private_identity) =
            Self::login_private_identity(*account_id, &*access_point).await?;

        Ok(Self {
            folder,
            index,
            private_identity,
            devices: None,
        })
    }
}

impl From<IdentityFolder> for Vault {
    fn from(value: IdentityFolder) -> Self {
        value.folder.into()
    }
}
