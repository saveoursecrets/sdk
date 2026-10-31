//! Types for device support.
use crate::{Error, Result};
use secrecy::ExposeSecret;
use sos_backend::{
    AccessPoint, BackendTarget,
    database::entity::{AccountEntity, FolderEntity, FolderRow},
};
use sos_core::{
    AccountId, SecretId, VaultFlags,
    crypto::AccessKey,
    device::{DeviceMetaData, DevicePublicKey, TrustedDevice},
    encode,
};
use sos_filesystem::write_exclusive;
use sos_signer::ed25519::{self, BoxedEd25519Signer, SingleParty};
use sos_vault::{
    BuilderCredentials, SecretAccess, Vault, VaultBuilder,
    secret::{Secret, SecretSigner},
};
use urn::Urn;

/// Signing key for a device.
#[derive(Clone)]
pub struct DeviceSigner(pub(crate) BoxedEd25519Signer);

impl DeviceSigner {
    /// Create a new random device signing key.
    pub fn random() -> Self {
        let key = SingleParty::new_random();
        Self(Box::new(key))
    }

    /// Device signing key.
    pub fn signing_key(&self) -> &BoxedEd25519Signer {
        &self.0
    }

    /// Public verifying key as bytes.
    pub fn public_key(&self) -> DevicePublicKey {
        self.0.verifying_key().as_bytes().into()
    }

    /// Bytes for this signing key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes().try_into().unwrap()
    }
}

impl TryFrom<[u8; 32]> for DeviceSigner {
    type Error = Error;

    fn try_from(value: [u8; 32]) -> Result<Self> {
        let signer: SingleParty = value.try_into()?;
        Ok(Self(Box::new(signer)))
    }
}

impl From<DeviceSigner> for BoxedEd25519Signer {
    fn from(value: DeviceSigner) -> Self {
        value.0
    }
}

impl From<SingleParty> for DeviceSigner {
    fn from(value: SingleParty) -> Self {
        Self(Box::new(value))
    }
}

/// Manages the access point that protects the device signing key.
///
/// Call [DeviceManager::sign_out] to lock the device vault.
pub struct DeviceManager {
    /// Signing key for this device.
    signer: DeviceSigner,
    /// Access to the vault that stores the device
    /// signing key.
    access_point: AccessPoint,
}

impl DeviceManager {
    /// Initialize a new device manager.
    ///
    /// The access point should be unlocked before assigning to a
    /// device manager.
    fn init(signer: DeviceSigner, access_point: AccessPoint) -> Self {
        Self {
            signer,
            access_point,
        }
    }

    /// Create a new device manager from a signer.
    pub async fn new(
        target: &BackendTarget,
        account_id: &AccountId,
        signer: DeviceSigner,
        password: &AccessKey,
    ) -> Result<Self> {
        let device_vault = Self::create_device_vault(password).await?;
        let access_point = match target {
            BackendTarget::FileSystem(paths) => {
                let buffer = encode(&device_vault).await?;
                write_exclusive(paths.device_file(), &buffer).await?;
                AccessPoint::from_path(paths.device_file(), device_vault)
            }
            BackendTarget::Database(_, client) => {
                let account_id = *account_id;
                let folder_row = FolderRow::new_insert(&device_vault).await?;
                client
                    .conn(move |conn| {
                        let account = AccountEntity::new(&conn);
                        let folder = FolderEntity::new(&conn);
                        let account_row = account.find_one(&account_id)?;
                        let folder_id = folder
                            .insert_folder(account_row.row_id, &folder_row)?;
                        account.insert_device_folder(
                            account_row.row_id,
                            folder_id,
                        )
                    })
                    .await
                    .map_err(sos_backend::database::Error::from)?;
                AccessPoint::new(target.clone(), device_vault).await
            }
        };
        Ok(Self::init(signer, access_point))
    }

    /// Load a device manager from an existing vault.
    pub async fn open_vault(
        target: BackendTarget,
        vault: Vault,
        access_key: &AccessKey,
    ) -> Result<(Self, SecretId)> {
        let device_key_urn = Self::device_urn()?;
        tracing::debug!(
            urn = %device_key_urn,
            backend_target = %target,
            "device::open_vault");

        let mut device_keeper = AccessPoint::new(target, vault).await;
        device_keeper.unlock(access_key).await?;

        // Try to find the device signing key
        let mut device_signer_secret: Option<(SecretId, Secret)> = None;
        for id in device_keeper.vault().keys() {
            if let Some((meta, secret, _)) =
                device_keeper.read_secret(id).await?
                && let Some(urn) = meta.urn()
                && urn == &device_key_urn
            {
                device_signer_secret = Some((*id, secret));
                break;
            }
        }

        if let Some((
            id,
            Secret::Signer {
                private_key: SecretSigner::SinglePartyEd25519(data),
                ..
            },
        )) = device_signer_secret
        {
            let key: ed25519::SingleParty =
                data.expose_secret().as_slice().try_into()?;
            Ok((DeviceManager::init(key.into(), device_keeper), id))
        } else {
            Err(Error::VaultEntryKind(device_key_urn.to_string()))
        }
    }

    pub(crate) fn device_urn() -> Result<Urn> {
        use sos_core::constants::DEVICE_KEY_URN;
        Ok(DEVICE_KEY_URN.parse()?)
    }

    async fn create_device_vault(password: &AccessKey) -> Result<Vault> {
        // Prepare the device vault
        let vault = VaultBuilder::new()
            .public_name("Device".to_string())
            .flags(
                VaultFlags::SYSTEM | VaultFlags::DEVICE | VaultFlags::NO_SYNC,
            )
            .build(BuilderCredentials::Password(
                password.clone().into(),
                None,
            ))
            .await?;

        Ok(vault)
    }

    /// Access point for the device vault.
    pub(crate) fn access_point(&self) -> &AccessPoint {
        &self.access_point
    }

    /// Mutable access point for the device vault.
    pub(crate) fn access_point_mut(&mut self) -> &mut AccessPoint {
        &mut self.access_point
    }

    /// Signing key for this device.
    pub(crate) fn signer(&self) -> &DeviceSigner {
        &self.signer
    }

    /// Consume this device manager into a buffer of the vault.
    pub async fn into_vault_buffer(self) -> Result<Vec<u8>> {
        let vault: Vault = self.access_point.into();
        let buffer = encode(&vault).await?;
        Ok(buffer)
    }

    /// Current device information.
    pub fn current_device(
        &self,
        extra_info: Option<DeviceMetaData>,
    ) -> TrustedDevice {
        TrustedDevice::new(self.signer.public_key(), extra_info, None)
    }

    /// Sign out locking the device vault.
    pub fn sign_out(&mut self) {
        self.access_point.lock();
    }
}
