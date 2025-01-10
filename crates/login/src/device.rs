//! Types for device support.
use crate::{Error, Result};
use sos_backend::AccessPoint;
use sos_core::{
    device::{DeviceMetaData, DevicePublicKey, TrustedDevice},
    encode,
};
use sos_signer::ed25519::{BoxedEd25519Signer, SingleParty};
use sos_vault::{SecretAccess, Vault};

/// Signing key for a device.
#[derive(Clone)]
pub struct DeviceSigner(pub(crate) BoxedEd25519Signer);

impl DeviceSigner {
    /// Create a new random device signing key.
    pub fn new_random() -> Self {
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
    keeper: AccessPoint,
}

impl DeviceManager {
    /// Create a new device manager.
    ///
    /// The access point should be unlocked before assigning to a
    /// device manager.
    pub(super) fn new(signer: DeviceSigner, keeper: AccessPoint) -> Self {
        Self { signer, keeper }
    }

    /// Signing key for this device.
    pub(crate) fn signer(&self) -> &DeviceSigner {
        &self.signer
    }

    /// Consume this device manager into a buffer of the vault.
    pub async fn into_vault_buffer(self) -> Result<Vec<u8>> {
        let vault: Vault = self.keeper.into();
        let buffer = encode(&vault).await?;
        Ok(buffer)
    }

    /// Basic device information.
    ///
    /// Most applications will want to use other platform native
    /// code to get more information about the device hardware.
    pub fn device_info() -> DeviceMetaData {
        Default::default()
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
        self.keeper.lock();
    }
}
