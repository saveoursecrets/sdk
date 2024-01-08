//! Enroll a device to an account on a remote server.
use crate::{
    client::{sync::RemoteSync, Error, NetworkAccount, Origin, Result},
    sdk::{
        crypto::AccessKey,
        device::DeviceSigner,
        encode,
        events::{
            AccountEvent, AccountEventLog, EventLogExt, EventReducer,
            FolderEventLog, WriteEvent,
        },
        signer::ecdsa::Address,
        sync::{AccountPatch, Client, FolderPatch},
        vault::VaultId,
        vfs, Paths,
    },
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

#[cfg(feature = "device")]
use crate::sdk::{
    device::TrustedDevice,
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
    /// Device signing key.
    pub(crate) device_signing_key: DeviceSigner,
}

impl DeviceEnrollment {
    /// Create a new device enrollment.
    pub fn new(
        address: &Address,
        data_dir: Option<PathBuf>,
        origin: Origin,
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
            device_signing_key: DeviceSigner::new_random(),
        })
    }

    /// Prepare to enroll this device to an account using the
    /// given client to fetch the account data.
    pub async fn enroll(&self, client: impl Client) -> Result<()> {
        let identity_vault = self.paths.identity_vault();
        if vfs::try_exists(&identity_vault).await? {
            return Err(Error::EnrollAccountExists(
                self.paths.user_id().to_owned(),
            ));
        }

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
            Err(_) => Err(Error::EnrollFetch(client.url().to_string())),
        }
    }

    /// Finish device enrollment by authenticating the new account.
    pub async fn finish(&self, key: &AccessKey) -> Result<NetworkAccount> {
        let mut account = NetworkAccount::new_unauthenticated(
            self.address.clone(),
            self.data_dir.clone(),
            None,
        )
        .await?;

        // Add the remote origin so it is loaded as
        // a remote when the sign in is successful
        account.add_origin(self.origin.clone()).await?;

        // Sign in to the new account
        account.sign_in(key).await?;

        // Sync to save the amended device event log
        // to the remote server
        account.sync().await.ok_or_else(|| {
            Error::EnrollSync(self.origin.url().to_string())
        })?;

        Ok(account)
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

        // Include this device in the list of trusted devices
        // stored locally.
        //
        // This update must be propagated to the server on the
        // next successful sync which should happen once the
        // user logs in to the account to complete the device
        // enrollment.
        let device = TrustedDevice::new(
            self.device_signing_key.public_key(),
            None,
            None,
        );
        let event = DeviceEvent::Trust(device);
        event_log.apply(vec![&event]).await?;

        Ok(())
    }

    async fn create_identity(&self, patch: FolderPatch) -> Result<()> {
        let events = self.paths.identity_events();
        let vault = self.paths.identity_vault();
        self.create_folder(events, vault, patch).await
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

        let vault = EventReducer::new()
            .reduce(&event_log)
            .await?
            .build(true)
            .await?;

        let buffer = encode(&vault).await?;
        vfs::write(vault_path.as_ref(), buffer).await?;

        Ok(())
    }
}
