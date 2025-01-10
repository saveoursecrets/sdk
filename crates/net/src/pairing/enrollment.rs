//! Enroll a device to an account on a remote server.
use crate::{
    pairing::{Error, Result},
    NetworkAccount,
};
use sos_account::Account;
use sos_backend::{
    reducers::FolderReducer, AccountEventLog, DeviceEventLog, FolderEventLog,
};
use sos_core::{
    crypto::AccessKey,
    encode,
    events::AccountEvent,
    events::{
        patch::{AccountPatch, DevicePatch, FolderPatch},
        EventLog,
    },
    AccountId, Origin, VaultId,
};
use sos_filesystem::VaultFileWriter;
use sos_protocol::{network_client::HttpClient, SyncClient};
use sos_sdk::{
    device::DeviceSigner,
    identity::{Identity, PublicIdentity},
    vault::EncryptedEntry,
    vfs, Paths,
};
use sos_signer::ed25519::BoxedEd25519Signer;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
};

/// Enroll a device.
///
/// Once pairing is completed call [DeviceEnrollment::fetch_account]
/// to retrieve the account data and then [DeviceEnrollment::finish]
/// to authenticate the account.
pub struct DeviceEnrollment {
    /// Account identifier.
    account_id: AccountId,
    /// Account paths.
    paths: Paths,
    /// Data directory.
    data_dir: Option<PathBuf>,
    /// Client used to fetch the account data.
    client: HttpClient,
    /// Public identity.
    ///
    /// This is available once the account data
    /// has been successfully fetched.
    public_identity: Option<PublicIdentity>,
    /// Device vault.
    device_vault: Vec<u8>,
    /// Account name extracted from the account event logs.
    account_name: Option<String>,
    /// Collection of server origins.
    servers: HashSet<Origin>,
}

impl DeviceEnrollment {
    /// Create a new device enrollment.
    pub(crate) async fn new(
        account_id: AccountId,
        origin: Origin,
        device_signer: DeviceSigner,
        device_vault: Vec<u8>,
        servers: HashSet<Origin>,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let paths = if let Some(data_dir) = &data_dir {
            Paths::new(data_dir.clone(), account_id.to_string())
        } else {
            Paths::new(Paths::data_dir()?, account_id.to_string())
        };

        let device_signing_key = device_signer.clone();
        let device: BoxedEd25519Signer = device_signing_key.into();
        let client =
            HttpClient::new(account_id, origin, device, String::new())?;

        Ok(Self {
            account_id,
            paths,
            data_dir,
            client,
            public_identity: None,
            device_vault,
            account_name: None,
            servers,
        })
    }

    /// Account identifier.
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
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
        self.create_device(change_set.device).await?;
        self.create_identity(change_set.identity).await?;

        // Got an account name change event so update the name
        // of the identity vault
        if let Some(account_name) = self.account_name.take() {
            let path = self.paths.identity_vault();
            let mut file = VaultFileWriter::<Error>::new(&path).await?;
            file.set_vault_name(account_name).await?;
        }

        // Write the vault containing the device signing key
        vfs::write_exclusive(self.paths.device_file(), &self.device_vault)
            .await?;

        // Add origin servers early so that they will be registered
        // as remotes when the enrollment is finished and the account
        // is authenticated
        self.add_origin_servers().await?;

        Ok(())
    }

    /// Finish device enrollment by authenticating the new account.
    pub async fn finish(&self, key: &AccessKey) -> Result<NetworkAccount> {
        self.public_identity
            .as_ref()
            .ok_or_else(|| Error::AccountNotFetched)?;

        let mut account = NetworkAccount::new_unauthenticated(
            self.account_id,
            self.data_dir.clone(),
            Default::default(),
        )
        .await?;

        // Sign in to the new account
        account.sign_in(key).await?;

        Ok(account)
    }

    /// Add the server origins to the enrolled account paths.
    async fn add_origin_servers(&self) -> Result<()> {
        let remotes_file = self.paths.remote_origins();
        let data = serde_json::to_vec_pretty(&self.servers)?;
        vfs::write_exclusive(remotes_file, data).await?;
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

    async fn create_account(&mut self, patch: AccountPatch) -> Result<()> {
        let file = self.paths.account_events();
        let mut event_log =
            AccountEventLog::new_file_system_account(file).await?;
        event_log.clear().await?;

        // let events: Vec<AccountEvent> = patch.into();
        for record in patch.iter() {
            let event = record.decode_event::<AccountEvent>().await?;
            if let AccountEvent::RenameAccount(account_name) = event {
                self.account_name = Some(account_name.to_string());
            }
        }
        event_log.patch_unchecked(&patch).await?;
        Ok(())
    }

    async fn create_device(&self, patch: DevicePatch) -> Result<()> {
        let file = self.paths.device_events();
        let mut event_log =
            DeviceEventLog::new_file_system_device(file).await?;
        event_log.clear().await?;

        // let events: Vec<DeviceEvent> = patch.into();
        event_log.patch_unchecked(&patch).await?;

        Ok(())
    }

    async fn create_identity(&mut self, patch: FolderPatch) -> Result<()> {
        let events = self.paths.identity_events();
        let vault = self.paths.identity_vault();
        self.create_folder(events, &vault, patch).await?;
        self.public_identity = Identity::read_public_identity(vault).await?;
        Ok(())
    }

    async fn create_folder(
        &self,
        events_path: impl AsRef<Path>,
        vault_path: impl AsRef<Path>,
        patch: FolderPatch,
    ) -> Result<()> {
        let mut event_log =
            FolderEventLog::new_file_system_folder(events_path.as_ref())
                .await?;
        event_log.clear().await?;

        // let events: Vec<WriteEvent> = patch.into();
        event_log.patch_unchecked(&patch).await?;

        let vault = FolderReducer::new()
            .reduce(&event_log)
            .await?
            .build(true)
            .await?;

        let buffer = encode(&vault).await?;
        vfs::write_exclusive(vault_path.as_ref(), buffer).await?;

        Ok(())
    }
}
