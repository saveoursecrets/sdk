//! Enroll a device to an account on a remote server.
use crate::{
    client::{
        pairing::{Error, Result},
        HttpClient, NetworkAccount,
    },
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
        signer::{
            ecdsa::{Address, BoxedEcdsaSigner},
            ed25519::BoxedEd25519Signer,
        },
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

/// Enroll a device.
///
/// Once pairing is completed call [DeviceEnrollment::fetch_account]
/// to retrieve the account data and then [DeviceEnrollment::finish]
/// to authenticate the account.
pub struct DeviceEnrollment {
    /// Account address.
    address: Address,
    /// Account paths.
    paths: Paths,
    /// Data directory.
    data_dir: Option<PathBuf>,
    /// Remote server origin.
    origin: Origin,
    /// Client used to fetch the account data.
    client: HttpClient,
    /// Public identity.
    ///
    /// This is available once the account data
    /// has been successfully fetched.
    public_identity: Option<PublicIdentity>,
    /// Device vault.
    device_vault: Vec<u8>,
}

impl DeviceEnrollment {
    /// Create a new device enrollment.
    pub(crate) async fn new(
        account_signing_key: BoxedEcdsaSigner,
        origin: Origin,
        device_signer: DeviceSigner,
        device_vault: Vec<u8>,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let address = account_signing_key.address()?;
        let paths = if let Some(data_dir) = &data_dir {
            Paths::new(data_dir.clone(), address.to_string())
        } else {
            Paths::new(Paths::data_dir()?, address.to_string())
        };

        let device_signing_key = device_signer.clone();
        let device: BoxedEd25519Signer = device_signing_key.into();

        let client = HttpClient::new(
            origin.clone(),
            account_signing_key,
            device,
            String::new(),
        )?;

        Ok(Self {
            address: address.to_owned(),
            paths,
            data_dir,
            origin,
            client,
            public_identity: None,
            device_vault,
        })
    }

    /// Account address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Public identity of the account.
    ///
    /// Only available after a successful call to
    /// [DeviceEnrollment::fetch_account].
    pub fn public_identity(&self) -> Option<&PublicIdentity> {
        self.public_identity.as_ref()
    }

    /// Fetch the account data for this enrollment.
    pub async fn fetch_account(&mut self) -> Result<()> {
        let identity_vault = self.paths.identity_vault();
        if vfs::try_exists(&identity_vault).await? {
            return Err(Error::EnrollAccountExists(
                self.paths.user_id().to_owned(),
            ));
        }

        Paths::scaffold(self.data_dir.clone()).await?;
        self.paths.ensure().await?;

        let change_set = self.client.fetch_account().await?;
        self.create_folders(change_set.folders).await?;
        self.create_account(change_set.account).await?;
        #[cfg(feature = "device")]
        self.create_device(change_set.device).await?;
        self.create_identity(change_set.identity).await?;

        // Write the vault containing the device signing key
        vfs::write(self.paths.device_file(), &self.device_vault).await?;

        // Add the remote origin so it is loaded as
        // a remote on the next sign in
        self.add_origin().await?;

        Ok(())
    }

    /// Finish device enrollment by authenticating the new account.
    pub async fn finish(&self, key: &AccessKey) -> Result<NetworkAccount> {
        self.public_identity
            .as_ref()
            .ok_or_else(|| Error::AccountNotFetched)?;

        let mut account = NetworkAccount::new_unauthenticated(
            self.address.clone(),
            self.data_dir.clone(),
            false,
        )
        .await?;

        // Sign in to the new account
        account.sign_in(key).await?;

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