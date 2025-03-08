//! Login identity folder management.
//!
//! Provides access to an identity folder containing
//! delegated passwords used to decrypt folders managed
//! by an account.
use crate::{
    device::{DeviceManager, DeviceSigner},
    DelegatedAccess, Error, PrivateIdentity, Result, UrnLookup,
};
use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretBox, SecretString};
use sos_backend::{
    database::entity::{AccountEntity, AccountRow, FolderEntity, FolderRow},
    AccessPoint, BackendTarget, Folder, FolderEventLog,
};
use sos_core::{
    constants::LOGIN_AGE_KEY_URN, crypto::AccessKey, encode, AccountId,
    AuthenticationError,
};
use sos_filesystem::write_exclusive;
use sos_vault::Summary;
use sos_vault::{
    secret::{Secret, SecretId, SecretMeta, SecretRow, SecretSigner},
    BuilderCredentials, SecretAccess, Vault, VaultBuilder, VaultFlags,
    VaultId,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use urn::Urn;

/// Identity folder stores delegated passwords and an
/// asymmetric encryption key.
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
    /// Create a new identity folder.
    pub async fn new(
        target: BackendTarget,
        name: String,
        password: SecretString,
        account_id: Option<AccountId>,
    ) -> Result<Self> {
        let account_id = account_id.unwrap_or_else(AccountId::random);
        let target = target.with_account_id(&account_id);
        tracing::debug!(
            account_id = %account_id,
            backend_target = %target,
            "new_identity_folder");

        let vault =
            Self::create_identity_vault(name.clone(), &password).await?;

        let mut folder = match &target {
            BackendTarget::FileSystem(paths) => {
                let buffer = encode(&vault).await?;
                write_exclusive(paths.identity_vault(), buffer).await?;
                Folder::from_path(paths.identity_vault()).await?
            }
            BackendTarget::Database(_, client) => {
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
                Folder::new(target, &account_id, vault.id()).await?
            }
        };

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

    /// Reference to the folder.
    pub fn folder(&self) -> &Folder {
        &self.folder
    }

    /// Folder event log.
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
    pub(super) async fn ensure_device_vault(
        &mut self,
        target: BackendTarget,
    ) -> Result<()> {
        let account_id = self.private_identity.account_id();
        let device_vault = target.read_device_vault(account_id).await?;
        let device_manager = if let Some(vault) = device_vault {
            let device_password = self
                .find_folder_password(vault.id())
                .await?
                .ok_or(Error::NoFolderPassword(*vault.id()))?;
            let key: AccessKey = device_password.into();

            let (device_manager, id) =
                DeviceManager::open_vault(target, vault, &key).await?;

            // Add to the URN lookup index
            let urn = DeviceManager::device_urn()?;
            self.index
                .insert((*device_manager.access_point().id(), urn), id);

            device_manager
        } else {
            self.new_device_manager(&target, DeviceSigner::new_random())
                .await?
        };
        self.devices = Some(device_manager);
        Ok(())
    }

    /// Create a device manager from a signer.
    pub async fn new_device_manager(
        &mut self,
        target: &BackendTarget,
        signer: DeviceSigner,
    ) -> Result<DeviceManager> {
        let account_id = self.private_identity.account_id();
        let password = self.generate_folder_password()?;
        let key = password.into();

        let mut device_manager =
            DeviceManager::new(target, account_id, signer.clone(), &key)
                .await?;

        let folder_id = *device_manager.access_point().id();
        let device_key_urn = DeviceManager::device_urn()?;

        tracing::debug!(
            urn = %device_key_urn,
            "create_device_manager");

        self.save_folder_password(&folder_id, key.clone()).await?;

        // let key: AccessKey = device_password.into();
        device_manager.access_point_mut().unlock(&key).await?;

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
        device_manager
            .access_point_mut()
            .create_secret(&secret_data)
            .await?;

        {
            self.index.insert((folder_id, device_key_urn), id);
        }

        Ok(device_manager)
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

    /// Login to an identity folder.
    pub async fn login(
        target: &BackendTarget,
        account_id: &AccountId,
        key: &AccessKey,
    ) -> Result<Self> {
        let target = target.clone().with_account_id(account_id);
        let mut folder = match &target {
            BackendTarget::FileSystem(paths) => {
                Folder::from_path(paths.identity_vault()).await?
            }
            BackendTarget::Database(_, client) => {
                let (_, login_folder) =
                    AccountEntity::find_account_with_login(
                        client, account_id,
                    )
                    .await?;

                Folder::new(target, account_id, login_folder.summary.id())
                    .await?
            }
        };

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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DelegatedAccess for IdentityFolder {
    type Error = Error;

    async fn find_folder_password(
        &self,
        folder_id: &VaultId,
    ) -> Result<Option<AccessKey>> {
        let urn = Vault::vault_urn(folder_id)?;
        let login_folder_id = self.folder.id().await;

        tracing::debug!(
            login_folder_id = %login_folder_id,
            folder_id = %folder_id,
            urn = %urn,
            "find_folder_password");

        if let Some(id) = self.index.get(&(login_folder_id, urn.clone())) {
            let (_, secret, _) = self
                .folder
                .read_secret(id)
                .await?
                .ok_or_else(|| Error::NoSecretId(login_folder_id, *id))?;

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

    async fn remove_folder_password(
        &mut self,
        folder_id: &VaultId,
    ) -> Result<()> {
        tracing::debug!(folder = %folder_id, "remove_folder_password");

        let (id, index_key) = {
            let urn = Vault::vault_urn(folder_id)?;
            let index_key = (self.folder.id().await, urn);
            let id = self.index.get(&index_key);
            (id, index_key)
        };

        if let Some(id) = &id {
            self.folder.delete_secret(&id).await?;
        } else {
            tracing::warn!("remove_folder_password::secret_id_not_found");
        }
        self.index.remove(&index_key);

        Ok(())
    }

    async fn save_folder_password(
        &mut self,
        folder_id: &VaultId,
        key: AccessKey,
    ) -> Result<()> {
        let urn = Vault::vault_urn(folder_id)?;
        tracing::debug!(
            folder = %folder_id,
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
}
