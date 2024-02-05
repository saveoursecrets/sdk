//! Enroll a device to an account on a remote server.
use crate::{
    client::{sync::RemoteSync, Error, NetworkAccount, Result},
    sdk::{
        account::Account,
        crypto::AccessKey,
        device::DeviceSigner,
        encode,
        events::{
            AccountEvent, AccountEventLog, EventLogExt, FolderEventLog,
            FolderReducer, WriteEvent,
        },
        identity::PublicIdentity,
        signer::ecdsa::Address,
        sync::{AccountPatch, FolderPatch, Origin, SyncClient},
        vault::VaultId,
        vfs, Paths,
    },
};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

#[cfg(feature = "device")]
use crate::sdk::{
    events::{DeviceEvent, DeviceEventLog},
    sync::DevicePatch,
};

/// Enroll a device to a remote server account.
pub struct DeviceEnrollment {
    /// Account address.
    address: Address,
    /// Account paths.
    paths: Paths,
    /// Data directory.
    data_dir: Option<PathBuf>,
    /// Remote server origin.
    origin: Origin,
    /// Public identity.
    ///
    /// This is available once the account data
    /// has been successfully fetched.
    public_identity: Option<PublicIdentity>,
    /// Device signing key.
    pub(crate) device_signing_key: DeviceSigner,
}

impl DeviceEnrollment {
    /// Create a new device enrollment.
    pub fn new(
        address: &Address,
        origin: Origin,
        device_signer: DeviceSigner,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let paths = if let Some(data_dir) = &data_dir {
            Paths::new(data_dir.clone(), address.to_string())
        } else {
            Paths::new(Paths::data_dir()?, address.to_string())
        };

        Ok(Self {
            address: address.to_owned(),
            paths,
            data_dir,
            origin,
            device_signing_key: device_signer,
            public_identity: None,
        })
    }

    /// Public identity of the account.
    ///
    /// Only available after a successful call to [DeviceEnrollment::enroll].
    pub fn public_identity(&self) -> Option<&PublicIdentity> {
        self.public_identity.as_ref()
    }

    /// Prepare to enroll this device to an account using the
    /// given client to fetch the account data.
    pub async fn enroll(&mut self, client: impl SyncClient) -> Result<()> {
        let identity_vault = self.paths.identity_vault();
        if vfs::try_exists(&identity_vault).await? {
            return Err(Error::EnrollAccountExists(
                self.paths.user_id().to_owned(),
            ));
        }

        Paths::scaffold(self.data_dir.clone()).await?;
        self.paths.ensure().await?;

        match client.fetch_account().await {
            Ok(change_set) => {
                self.create_folders(change_set.folders).await?;
                self.create_account(change_set.account).await?;
                #[cfg(feature = "device")]
                self.create_device(change_set.device).await?;
                self.create_identity(change_set.identity).await?;
                Ok(())
            }
            Err(e) => {
                tracing::error!(error = ?e);
                Err(Error::EnrollFetch(client.origin().url().to_string()))
            }
        }
    }

    /// Finish device enrollment by authenticating the new account.
    pub async fn finish(&self, key: &AccessKey) -> Result<NetworkAccount> {
        let mut account = NetworkAccount::new_unauthenticated(
            self.address.clone(),
            self.data_dir.clone(),
        )
        .await?;

        // Add the remote origin so it is loaded as
        // a remote when the sign in is successful
        self.add_origin().await?;

        // Ensure the correct device signing key is saved
        // when lazily creating the device vault
        let _ = crate::sdk::device::DEVICE_SIGNER
            .set(self.device_signing_key.clone());

        // Sign in to the new account
        account.sign_in(key).await?;

        // Sync to save the amended identity folder on the remote
        if let Some(e) = account.sync().await {
            println!("{:#?}", e);
            tracing::error!(error = ?e);
            return Err(Error::EnrollSync(self.origin.url().to_string()));
        }

        Ok(account)
    }

    /// Add a remote origin to the enrolled account paths.
    async fn add_origin(&self) -> Result<()> {
        let remotes_file = self.paths.remote_origins();
        let mut origins = if vfs::try_exists(&remotes_file).await? {
            let contents = vfs::read(&remotes_file).await?;
            let origins: HashSet<Origin> = serde_json::from_slice(&contents)?;
            origins
        } else {
            HashSet::new()
        };

        origins.insert(self.origin.clone());

        let data = serde_json::to_vec_pretty(&origins)?;
        vfs::write(remotes_file, data).await?;

        Ok(())
    }

    async fn create_folders(
        &self,
        folders: HashMap<VaultId, FolderPatch>,
    ) -> Result<()> {
        for (id, patch) in folders {
            let events = self.paths.event_log_path(&id);
            let vault = self.paths.vault_path(&id);
            self.create_folder(events, vault, patch).await?;
        }
        Ok(())
    }

    async fn create_account(&self, patch: AccountPatch) -> Result<()> {
        let file = self.paths.account_events();
        let mut event_log = AccountEventLog::new_account(file).await?;
        event_log.clear().await?;

        let events: Vec<AccountEvent> = patch.into();
        event_log.apply(events.iter().collect()).await?;

        Ok(())
    }

    #[cfg(feature = "device")]
    async fn create_device(&self, patch: DevicePatch) -> Result<()> {
        let file = self.paths.device_events();
        let mut event_log = DeviceEventLog::new_device(file).await?;
        event_log.clear().await?;

        let events: Vec<DeviceEvent> = patch.into();
        event_log.apply(events.iter().collect()).await?;

        Ok(())
    }

    async fn create_identity(&mut self, patch: FolderPatch) -> Result<()> {
        let events = self.paths.identity_events();
        let vault = self.paths.identity_vault();
        self.create_folder(events, &vault, patch).await?;
        self.public_identity =
            PublicIdentity::read_public_identity(vault).await?;
        Ok(())
    }

    async fn create_folder(
        &self,
        events_path: impl AsRef<Path>,
        vault_path: impl AsRef<Path>,
        patch: FolderPatch,
    ) -> Result<()> {
        let mut event_log = FolderEventLog::new(events_path.as_ref()).await?;
        event_log.clear().await?;

        let events: Vec<WriteEvent> = patch.into();
        event_log.apply(events.iter().collect()).await?;

        let vault = FolderReducer::new()
            .reduce(&event_log)
            .await?
            .build(true)
            .await?;

        let buffer = encode(&vault).await?;
        vfs::write(vault_path.as_ref(), buffer).await?;

        Ok(())
    }
}
