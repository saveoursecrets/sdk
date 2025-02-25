//! Enroll a device to an account on a remote server.
use crate::{
    pairing::{Error, Result},
    NetworkAccount,
};
use sos_account::Account;
use sos_backend::{BackendTarget, ServerOrigins};
use sos_client_storage::{
    ClientAccountStorage, ClientFolderStorage, ClientStorage,
};
use sos_core::{
    crypto::AccessKey, events::AccountEvent, AccountId, Origin,
    PublicIdentity, RemoteOrigins,
};
use sos_login::device::DeviceSigner;
use sos_protocol::{network_client::HttpClient, SyncClient};
use sos_signer::ed25519::BoxedEd25519Signer;
use std::collections::HashSet;

/// Enroll a device.
///
/// Once pairing is completed call [DeviceEnrollment::fetch_account]
/// to retrieve the account data and then [DeviceEnrollment::finish]
/// to authenticate the account.
pub struct DeviceEnrollment {
    /// Account identifier.
    account_id: AccountId,
    /// Client account storage.
    storage: ClientStorage,
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
        target: BackendTarget,
        account_id: AccountId,
        origin: Origin,
        device_signer: DeviceSigner,
        device_vault: Vec<u8>,
        servers: HashSet<Origin>,
    ) -> Result<Self> {
        let target = target.with_account_id(&account_id);
        let accounts = target.list_accounts().await?;
        if accounts
            .iter()
            .find(|a| a.account_id() == &account_id)
            .is_some()
        {
            return Err(Error::EnrollAccountExists(account_id));
        }

        let storage =
            ClientStorage::new_unauthenticated(target, &account_id).await?;

        let device_signing_key = device_signer.clone();
        let device: BoxedEd25519Signer = device_signing_key.into();
        let client =
            HttpClient::new(account_id, origin, device, String::new())?;
        Ok(Self {
            account_id,
            storage,
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
        let change_set = self.client.fetch_account().await?;

        // Find out if the account has been renamed
        for record in change_set.account.iter() {
            let event = record.decode_event::<AccountEvent>().await?;
            if let AccountEvent::RenameAccount(account_name) = event {
                self.account_name = Some(account_name.to_string());
            }
        }

        // Create the account data in storage
        self.storage.import_account(&change_set).await?;

        /*
        // Got an account name change event so update the name
        // of the identity vault
        if let Some(account_name) = self.account_name.take() {
            let path = self.paths.identity_vault();
            let mut file = VaultWriter::new_fs(&path);
            file.set_vault_name(account_name).await?;
        }
        */

        // Read the login vault to extract public identity
        let login_vault = self.storage.read_login_vault().await?;
        self.public_identity = Some(PublicIdentity::new(
            self.account_id,
            login_vault.name().to_owned(),
        ));

        /*
        self.create_folders(change_set.folders).await?;
        self.create_account(change_set.account).await?;
        self.create_device(change_set.device).await?;
        self.create_identity(change_set.identity).await?;

        // Got an account name change event so update the name
        // of the identity vault
        if let Some(account_name) = self.account_name.take() {
            let path = self.paths.identity_vault();
            let mut file = VaultWriter::new_fs(&path);
            file.set_vault_name(account_name).await?;
        }
        */

        // TODO: must write out the device vault to storage!!!

        /*
        // Write the vault containing the device signing key
        write_exclusive(self.paths.device_file(), &self.device_vault).await?;
        */

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
            self.storage.backend_target().clone(),
            Default::default(),
        )
        .await?;

        // Sign in to the new account
        account.sign_in(key).await?;

        Ok(account)
    }

    /// Add the server origins to the enrolled account paths.
    async fn add_origin_servers(&self) -> Result<()> {
        let mut origins = ServerOrigins::new(
            self.storage.backend_target().clone(),
            &self.account_id,
        );
        for server in &self.servers {
            origins.add_server(server.clone()).await?;
        }
        Ok(())
    }

    /*
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
    */

    /*
    async fn create_account(&mut self, patch: AccountPatch) -> Result<()> {
        let mut event_log = AccountEventLog::new_account(
            self.storage.backend_target().clone(),
            &self.account_id,
        )
        .await?;
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
    */

    /*
    async fn create_device(&self, patch: DevicePatch) -> Result<()> {
        let mut event_log = DeviceEventLog::new_device(
            self.storage.backend_target().clone(),
            &self.account_id,
        )
        .await?;
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
            FolderEventLog::new_fs_folder(events_path.as_ref()).await?;
        event_log.clear().await?;

        // let events: Vec<WriteEvent> = patch.into();
        event_log.patch_unchecked(&patch).await?;

        let vault = FolderReducer::new()
            .reduce(&event_log)
            .await?
            .build(true)
            .await?;

        let buffer = encode(&vault).await?;
        write_exclusive(vault_path.as_ref(), buffer).await?;

        Ok(())
    }
    */
}
