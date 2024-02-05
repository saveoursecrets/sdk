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
        hex,
        identity::PublicIdentity,
        signer::ecdsa::{Address, BoxedEcdsaSigner, SingleParty},
        sync::{AccountPatch, FolderPatch, Origin, SyncClient},
        url::Url,
        vault::VaultId,
        vfs, Paths,
    },
};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    str::FromStr,
};

#[cfg(feature = "device")]
use crate::sdk::{
    device::TrustedDevice,
    events::{DeviceEvent, DeviceEventLog},
    sync::DevicePatch,
};

/// URL for sharing a server and signing key.
///
/// This URL contains sensitive private key material and should
/// only be used by an account owner to enroll new devices.
///
/// The account owner must never give this URL to anybody else.
#[deprecated]
pub struct DeviceShareUrl {
    /// Server used to transfer the account data.
    server: Url,
    /// Account signing key.
    signing_key: BoxedEcdsaSigner,
}

impl DeviceShareUrl {
    /// Create a URL for sharing a server and signing key.
    pub fn new(server: Url, signing_key: BoxedEcdsaSigner) -> Self {
        Self {
            server,
            signing_key,
        }
    }

    /// Server URL.
    pub fn server(&self) -> &Url {
        &self.server
    }

    /// Account signing key.
    pub fn signing_key(&self) -> &BoxedEcdsaSigner {
        &self.signing_key
    }
}

impl From<DeviceShareUrl> for Url {
    fn from(value: DeviceShareUrl) -> Self {
        let mut url = Url::parse("data:text/plain,sos-enroll").unwrap();
        let key = hex::encode(value.signing_key.to_bytes());
        url.query_pairs_mut()
            .append_pair("url", &value.server.to_string())
            .append_pair("key", &key);

        url
    }
}

impl FromStr for DeviceShareUrl {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let url = Url::parse(s)?;

        if url.scheme() != "data" {
            return Err(Error::InvalidShareUrl);
        }

        if url.path() != "text/plain,sos-enroll" {
            return Err(Error::InvalidShareUrl);
        }

        let mut pairs = url.query_pairs();

        let server = pairs.find_map(|q| {
            if q.0.as_ref() == "url" {
                Some(q.1)
            } else {
                None
            }
        });

        let server = server.ok_or(Error::InvalidShareUrl)?;
        let server: Url = server.as_ref().parse()?;

        let key = pairs.find_map(|q| {
            if q.0.as_ref() == "key" {
                Some(q.1)
            } else {
                None
            }
        });
        let key = key.ok_or(Error::InvalidShareUrl)?;
        let key = hex::decode(key.as_ref())?;
        let key: [u8; 32] = key.as_slice().try_into()?;
        let key: SingleParty = key.try_into()?;

        Ok(Self {
            server,
            signing_key: Box::new(key),
        })
    }
}

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
        //event_log.clear().await?;

        let mut events: Vec<DeviceEvent> = patch.into();

        /*
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
        events.push(event);
        */

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
