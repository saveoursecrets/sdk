use super::{Error, Result};
use crate::{
    device::DeviceSet,
    sdk::{
        constants::{DEVICES_FILE, JSON_EXT},
        device::DevicePublicKey,
        signer::{
            ecdsa::Address,
            ed25519::{self, Verifier, VerifyingKey},
        },
        storage::{DiscFolder, ServerStorage},
        sync::ChangeSet,
        vfs, Paths,
    },
};
use async_trait::async_trait;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{span, Level};

/// Account storage.
pub struct AccountStorage {
    pub(crate) storage: ServerStorage,
    /// Set of trusted devices.
    devices: DeviceSet,
}

impl AccountStorage {
    /// Trust a device.
    pub async fn trust_device(
        &mut self,
        public_key: DevicePublicKey,
    ) -> Result<()> {
        self.devices.0.insert(public_key);
        self.save_devices().await?;
        Ok(())
    }

    /// Revoke trust in a device.
    pub async fn revoke_device(
        &mut self,
        public_key: &DevicePublicKey,
    ) -> Result<()> {
        self.devices.0.remove(public_key);
        self.save_devices().await?;
        Ok(())
    }

    /// List device public keys.
    pub fn list_device_keys(&self) -> &HashSet<DevicePublicKey> {
        &self.devices.0
    }

    /// Devices file for server-side storage.
    fn devices_file(&self) -> PathBuf {
        let mut path = self.storage.paths().user_dir().join(DEVICES_FILE);
        path.set_extension(JSON_EXT);
        path
    }

    async fn save_devices(&self) -> Result<()> {
        let path = self.devices_file();
        let contents = serde_json::to_vec(&self.devices)?;
        vfs::write(&path, contents).await?;
        Ok(())
    }

    async fn load_devices(&mut self) -> Result<()> {
        let path = self.devices_file();
        if vfs::try_exists(&path).await? {
            let contents = vfs::read(&path).await?;
            let devices: DeviceSet = serde_json::from_slice(&contents)?;
            self.devices = devices;
        }
        Ok(())
    }
}

/// Individual account.
pub type ServerAccount = Arc<RwLock<AccountStorage>>;

/// Collection of accounts by address.
pub type Accounts = Arc<RwLock<HashMap<Address, ServerAccount>>>;

/// Backend for a server.
pub enum Backend {
    /// File storage backend.
    FileSystem(FileSystemBackend),
}

impl Backend {
    /// Get a reference to the backend handler.
    pub fn handler(&self) -> &(impl BackendHandler + Send + Sync) {
        match self {
            Self::FileSystem(handler) => handler,
        }
    }

    /// Get a mutable reference to the backend handler.
    pub fn handler_mut(
        &mut self,
    ) -> &mut (impl BackendHandler + Send + Sync) {
        match self {
            Self::FileSystem(handler) => handler,
        }
    }

    /// Get the accounts map.
    pub fn accounts(&self) -> Accounts {
        match self {
            Self::FileSystem(handler) => handler.accounts(),
        }
    }
}

/// Trait for types that provide an interface to vault storage.
#[async_trait]
pub trait BackendHandler {
    /// Create a new account.
    async fn create_account(
        &mut self,
        owner: &Address,
        account_data: ChangeSet,
        device_public_key: DevicePublicKey,
    ) -> Result<()>;

    // TODO: support account deletion

    /// Determine if an account exists.
    async fn account_exists(&self, owner: &Address) -> Result<bool>;

    /// Trust a device.
    async fn trust_device(
        &mut self,
        owner: &Address,
        device_public_key: DevicePublicKey,
    ) -> Result<()>;

    /// Revoke trust in a device.
    async fn revoke_device(
        &mut self,
        owner: &Address,
        device_public_key: DevicePublicKey,
    ) -> Result<()>;

    /// Verify a device is allowed to access an account.
    async fn verify_device(
        &self,
        owner: &Address,
        device_signature: &ed25519::Signature,
        message_body: &[u8],
    ) -> Result<()>;
}

/// Backend storage for accounts on the file system.
pub struct FileSystemBackend {
    directory: PathBuf,
    accounts: Accounts,
}

impl FileSystemBackend {
    /// Create a new file system backend.
    pub fn new<P: AsRef<Path>>(directory: P) -> Self {
        let directory = directory.as_ref().to_path_buf();
        Self {
            directory,
            accounts: Arc::new(RwLock::new(Default::default())),
        }
    }

    /// Get the accounts.
    pub fn accounts(&self) -> Accounts {
        Arc::clone(&self.accounts)
    }

    /// Read accounts and event logs into memory.
    pub async fn read_dir(&mut self) -> Result<()> {
        if !vfs::metadata(&self.directory).await?.is_dir() {
            return Err(Error::NotDirectory(self.directory.clone()));
        }

        let span = span!(Level::DEBUG, "server init");
        let _enter = span.enter();
        tracing::debug!(directory = %self.directory.display());

        Paths::scaffold(Some(self.directory.clone())).await?;
        let paths = Paths::new_global_server(self.directory.clone());

        if !vfs::try_exists(paths.local_dir()).await? {
            vfs::create_dir(paths.local_dir()).await?;
        }

        let mut dir = vfs::read_dir(paths.local_dir()).await?;
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if vfs::metadata(&path).await?.is_dir() {
                if let Some(name) = path.file_stem() {
                    if let Ok(owner) =
                        name.to_string_lossy().parse::<Address>()
                    {
                        tracing::debug!(account = %owner);

                        let user_paths = Paths::new_server(
                            self.directory.clone(),
                            owner.to_string(),
                        );
                        let identity_log =
                            DiscFolder::new_event_log(&user_paths).await?;

                        let mut account = AccountStorage {
                            storage: ServerStorage::new(
                                owner.clone(),
                                Some(self.directory.clone()),
                                identity_log,
                            )
                            .await?,
                            devices: Default::default(),
                        };
                        account.load_devices().await?;

                        let mut accounts = self.accounts.write().await;
                        let account = accounts
                            .entry(owner.clone())
                            .or_insert(Arc::new(RwLock::new(account)));
                        let mut writer = account.write().await;
                        writer.storage.load_folders().await?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl BackendHandler for FileSystemBackend {
    async fn create_account(
        &mut self,
        owner: &Address,
        account_data: ChangeSet,
        device_public_key: DevicePublicKey,
    ) -> Result<()> {
        {
            let accounts = self.accounts.read().await;
            let account = accounts.get(owner);

            if account.is_some() {
                return Err(Error::AccountExists(*owner));
            }
        }

        let span = span!(Level::DEBUG, "create_account");
        let _enter = span.enter();
        tracing::debug!(address = %owner);

        let paths =
            Paths::new_server(self.directory.clone(), owner.to_string());
        paths.ensure().await?;

        let identity_log =
            ServerStorage::initialize_account(&paths, &account_data.identity)
                .await?;

        let mut storage = ServerStorage::new(
            owner.clone(),
            Some(self.directory.clone()),
            Arc::new(RwLock::new(identity_log)),
        )
        .await?;
        storage.import_account(&account_data).await?;

        let mut account = AccountStorage {
            storage,
            devices: Default::default(),
        };

        account.trust_device(device_public_key).await?;

        let mut accounts = self.accounts.write().await;
        accounts
            .entry(owner.clone())
            .or_insert(Arc::new(RwLock::new(account)));

        Ok(())
    }

    async fn trust_device(
        &mut self,
        owner: &Address,
        device_public_key: DevicePublicKey,
    ) -> Result<()> {
        let accounts = self.accounts.read().await;
        let account = accounts
            .get(owner)
            .ok_or(Error::NoAccount(owner.to_owned()))?;

        let mut writer = account.write().await;
        writer.trust_device(device_public_key).await?;
        Ok(())
    }

    async fn revoke_device(
        &mut self,
        owner: &Address,
        device_public_key: DevicePublicKey,
    ) -> Result<()> {
        let accounts = self.accounts.read().await;
        let account = accounts
            .get(owner)
            .ok_or(Error::NoAccount(owner.to_owned()))?;

        let mut writer = account.write().await;
        writer.revoke_device(&device_public_key).await?;
        Ok(())
    }

    /// Verify a device is allowed to access an account.
    async fn verify_device(
        &self,
        owner: &Address,
        device_signature: &ed25519::Signature,
        message_body: &[u8],
    ) -> Result<()> {
        let accounts = self.accounts.read().await;
        if let Some(account) = accounts.get(owner) {
            let reader = account.read().await;
            let account_devices = reader.list_device_keys();
            for device_key in account_devices {
                let verifying_key: VerifyingKey = device_key.try_into()?;
                if verifying_key
                    .verify(message_body, device_signature)
                    .is_ok()
                {
                    return Ok(());
                }
            }
            Err(Error::Forbidden)
        } else {
            Ok(())
        }
    }

    async fn account_exists(&self, owner: &Address) -> Result<bool> {
        let accounts = self.accounts.read().await;
        Ok(accounts.get(owner).is_some())
    }
}
