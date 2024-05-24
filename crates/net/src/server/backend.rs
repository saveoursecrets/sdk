use super::{Error, Result};
use crate::sdk::{
    signer::{
        ecdsa::Address,
        ed25519::{self, Verifier, VerifyingKey},
    },
    storage::{DiscFolder, ServerStorage},
    sync::{ChangeSet, SyncStorage, UpdateSet},
    vfs, Paths,
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;

#[cfg(feature = "device")]
use crate::sdk::sync::DeviceDiff;

/// Account storage.
pub struct AccountStorage {
    pub(crate) storage: ServerStorage,
}

/// Individual account.
pub type ServerAccount = Arc<RwLock<AccountStorage>>;

/// Collection of accounts by address.
pub type Accounts = Arc<RwLock<HashMap<Address, ServerAccount>>>;

/// Backend for a server.
pub struct Backend {
    directory: PathBuf,
    accounts: Accounts,
}

impl Backend {
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
    pub(crate) async fn read_dir(&mut self) -> Result<()> {
        if !vfs::metadata(&self.directory).await?.is_dir() {
            return Err(Error::NotDirectory(self.directory.clone()));
        }

        tracing::debug!(
            directory = %self.directory.display(), "backend::read_dir");

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
                        tracing::debug!(
                            account = %owner,
                            "backend::read_dir",
                        );

                        let user_paths = Paths::new_server(
                            self.directory.clone(),
                            owner.to_string(),
                        );
                        let identity_log =
                            DiscFolder::new_event_log(&user_paths).await?;

                        let account = AccountStorage {
                            storage: ServerStorage::new(
                                owner.clone(),
                                Some(self.directory.clone()),
                                identity_log,
                            )
                            .await?,
                        };

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

    /// Create an account.
    pub async fn create_account(
        &mut self,
        owner: &Address,
        account_data: ChangeSet,
    ) -> Result<()> {
        {
            let accounts = self.accounts.read().await;
            let account = accounts.get(owner);

            if account.is_some() {
                return Err(Error::AccountExists(*owner));
            }
        }

        tracing::debug!(address = %owner, "backend::create_account");

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

        let account = AccountStorage { storage };
        let mut accounts = self.accounts.write().await;
        accounts
            .entry(owner.clone())
            .or_insert(Arc::new(RwLock::new(account)));

        Ok(())
    }

    /// Update an account.
    pub async fn update_account(
        &mut self,
        owner: &Address,
        account_data: UpdateSet,
    ) -> Result<()> {
        tracing::debug!(address = %owner, "backend::update_account");

        let mut accounts = self.accounts.write().await;
        let account =
            accounts.get_mut(owner).ok_or(Error::NoAccount(*owner))?;

        let mut account = account.write().await;
        account.storage.update_account(account_data).await?;
        Ok(())
    }

    /// Fetch an existing account.
    pub async fn fetch_account(&self, owner: &Address) -> Result<ChangeSet> {
        tracing::debug!(address = %owner, "backend::fetch_account");

        let accounts = self.accounts.read().await;
        let account = accounts.get(owner).ok_or(Error::NoAccount(*owner))?;

        let reader = account.read().await;
        let change_set = reader.storage.change_set().await?;

        Ok(change_set)
    }

    /// Patch the devices event log.
    #[cfg(feature = "device")]
    pub async fn patch_devices(
        &self,
        owner: &Address,
        diff: &DeviceDiff,
    ) -> Result<()> {
        tracing::debug!(address = %owner, "backend::patch_devices");

        let accounts = self.accounts.read().await;
        let account = accounts.get(owner).ok_or(Error::NoAccount(*owner))?;

        let mut writer = account.write().await;
        writer.storage.patch_devices(diff).await?;

        Ok(())
    }

    /// Verify a device is allowed to access an account.
    pub(crate) async fn verify_device(
        &self,
        owner: &Address,
        device_signature: &ed25519::Signature,
        message_body: &[u8],
    ) -> Result<()> {
        let accounts = self.accounts.read().await;
        if let Some(account) = accounts.get(owner) {
            let reader = account.read().await;
            let account_devices = reader.storage.list_device_keys();
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

    /// Determine if an account exists.
    pub async fn account_exists(&self, owner: &Address) -> Result<bool> {
        let accounts = self.accounts.read().await;
        Ok(accounts.get(owner).is_some())
    }
}
