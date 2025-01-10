use super::{Error, Result};
use sos_backend::Folder;
use sos_core::{device::DevicePublicKey, AccountId, Paths};
use sos_server_storage::{
    filesystem::ServerFileStorage, ServerAccountStorage, ServerStorage,
};
use sos_signer::ed25519::{self, Verifier, VerifyingKey};
use sos_sync::{CreateSet, MergeOutcome, SyncStorage, UpdateSet};
use sos_vfs as vfs;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::RwLock;

/// Individual account.
pub type ServerAccount = Arc<RwLock<ServerStorage>>;

/// Collection of accounts by address.
pub type Accounts = Arc<RwLock<HashMap<AccountId, ServerAccount>>>;

fn into_device_verifying_key(
    value: &DevicePublicKey,
) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = value.as_ref().try_into()?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

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

    /// Directory where accounts are stored.
    pub fn directory(&self) -> &PathBuf {
        &self.directory
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
                        name.to_string_lossy().parse::<AccountId>()
                    {
                        tracing::debug!(
                            account = %owner,
                            "backend::read_dir",
                        );

                        let user_paths = Paths::new_server(
                            self.directory.clone(),
                            owner.to_string(),
                        );
                        let identity_log = Folder::new_fs_event_log(
                            user_paths.identity_events(),
                        )
                        .await?;

                        let account = ServerStorage::FileSystem(
                            ServerFileStorage::new(
                                owner.clone(),
                                Some(self.directory.clone()),
                                identity_log,
                            )
                            .await?,
                        );

                        let mut accounts = self.accounts.write().await;
                        let account = accounts
                            .entry(owner.clone())
                            .or_insert(Arc::new(RwLock::new(account)));
                        let mut writer = account.write().await;
                        writer.load_folders().await?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Create an account.
    pub async fn create_account(
        &mut self,
        owner: &AccountId,
        account_data: CreateSet,
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

        let identity_log = ServerFileStorage::initialize_account(
            &paths,
            &account_data.identity,
        )
        .await?;

        let mut storage = ServerFileStorage::new(
            owner.clone(),
            Some(self.directory.clone()),
            Arc::new(RwLock::new(identity_log)),
        )
        .await?;
        storage.import_account(&account_data).await?;

        let account = ServerStorage::FileSystem(storage);
        let mut accounts = self.accounts.write().await;
        accounts
            .entry(owner.clone())
            .or_insert(Arc::new(RwLock::new(account)));

        Ok(())
    }

    /// Delete an account.
    pub async fn delete_account(&mut self, owner: &AccountId) -> Result<()> {
        tracing::debug!(address = %owner, "backend::delete_account");

        let mut accounts = self.accounts.write().await;
        let account =
            accounts.get_mut(owner).ok_or(Error::NoAccount(*owner))?;

        let mut account = account.write().await;
        account.delete_account().await?;

        Ok(())
    }

    /// Update an account.
    pub async fn update_account(
        &mut self,
        owner: &AccountId,
        account_data: UpdateSet,
    ) -> Result<MergeOutcome> {
        tracing::debug!(address = %owner, "backend::update_account");

        let mut outcome = MergeOutcome::default();

        let mut accounts = self.accounts.write().await;
        let account =
            accounts.get_mut(owner).ok_or(Error::NoAccount(*owner))?;

        let mut account = account.write().await;
        account.update_account(account_data, &mut outcome).await?;
        Ok(outcome)
    }

    /// Fetch an existing account.
    pub async fn fetch_account(
        &self,
        owner: &AccountId,
    ) -> Result<CreateSet> {
        tracing::debug!(address = %owner, "backend::fetch_account");

        let accounts = self.accounts.read().await;
        let account = accounts.get(owner).ok_or(Error::NoAccount(*owner))?;

        let reader = account.read().await;
        let change_set = reader.change_set().await?;

        Ok(change_set)
    }

    /// Verify a device is allowed to access an account.
    pub(crate) async fn verify_device(
        &self,
        owner: &AccountId,
        device_signature: &ed25519::Signature,
        message_body: &[u8],
    ) -> Result<()> {
        let accounts = self.accounts.read().await;
        if let Some(account) = accounts.get(owner) {
            let reader = account.read().await;
            let account_devices = reader.list_device_keys();
            for device_key in account_devices {
                let verifying_key = into_device_verifying_key(device_key)?;
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
    pub async fn account_exists(&self, owner: &AccountId) -> Result<bool> {
        let accounts = self.accounts.read().await;
        Ok(accounts.get(owner).is_some())
    }
}
