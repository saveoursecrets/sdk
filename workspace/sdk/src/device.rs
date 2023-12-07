//! Types for device support.
use crate::{
    account::{Account, UserPaths},
    constants::DEVICES_NSS,
    identity::UrnLookup,
    signer::ed25519::{BoxedEd25519Signer, VerifyingKey},
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow},
        Gatekeeper, Summary,
    },
    vfs, Error, Result,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};
use time::OffsetDateTime;
use urn::Urn;

/// Encapsulate device specific information for an account.
#[derive(Clone)]
pub struct DeviceSigner {
    /// The vault containing device specific keys.
    pub(crate) summary: Summary,
    /// The signing key for this device.
    pub(crate) signer: BoxedEd25519Signer,
    /// The id of this device; Base58 encoded device public key.
    pub(crate) public_id: String,
}

impl DeviceSigner {
    /// Summary of the vault containing the device
    /// signing key.
    pub fn summary(&self) -> &Summary {
        &self.summary
    }

    /// Device signing key.
    pub fn signer(&self) -> &BoxedEd25519Signer {
        &self.signer
    }

    /// Identifier of the device public key.
    pub fn public_id(&self) -> &str {
        &self.public_id
    }

    /// Get the verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }
}

/// Manages the devices for a user.
pub struct DeviceManager {
    /// Signing key for this device.
    signer: DeviceSigner,
    /// Access to the vault that stores
    /// trusted device information for
    /// the account.
    keeper: Gatekeeper,
    /// Devices loaded into memory.
    devices: HashMap<String, TrustedDevice>,
    /// Lookup table by URN.
    lookup: UrnLookup,
}

impl DeviceManager {
    /// Create a new device manager.
    ///
    /// Device manager stores the signing key for this device and
    /// documents for devices that have been trusted by this device.
    ///
    /// Trusted device documents are stored as JSON in secret notes.
    ///
    /// The gatekeeper should be unlocked before assigning to a
    /// device manager.
    pub(super) fn new(signer: DeviceSigner, keeper: Gatekeeper) -> Self {
        Self {
            signer,
            keeper,
            devices: Default::default(),
            lookup: Default::default(),
        }
    }

    /// Load trusted devices.
    pub async fn load(&mut self) -> Result<()> {
        for id in self.keeper.vault().keys() {
            if let Some((meta, secret, _)) = self.keeper.read(id).await? {
                if let Some(urn) = meta.urn() {
                    if urn.nss().starts_with(DEVICES_NSS) {
                        let device_id: String = urn
                            .nss()
                            .trim_start_matches(DEVICES_NSS)
                            .to_owned();
                        if let Secret::Note { text, .. } = &secret {
                            let device: TrustedDevice =
                                serde_json::from_str(text.expose_secret())?;
                            self.devices.insert(device_id, device);
                            self.lookup.insert(
                                (*self.keeper.id(), urn.clone()),
                                *id,
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// List trusted devices.
    pub fn list_trusted_devices(&self) -> Vec<&TrustedDevice> {
        self.devices.values().collect()
    }

    /// Add a trusted device.
    pub async fn add_device(&mut self, device: TrustedDevice) -> Result<()> {
        let urn = device.device_urn()?;
        let device_id = device.public_id()?;
        let secret_id = SecretId::new_v4();
        let text = serde_json::to_string_pretty(&device)?;
        let secret = Secret::Note {
            text: SecretString::new(text),
            user_data: Default::default(),
        };
        let mut meta = SecretMeta::new(urn.to_string(), secret.kind());
        meta.set_urn(Some(urn.clone()));
        let secret_data = SecretRow::new(secret_id, meta, secret);
        self.keeper.create(&secret_data).await?;
        self.devices.insert(device_id, device);
        self.lookup.insert((*self.keeper.id(), urn), secret_id);
        Ok(())
    }

    /// Remove a trusted device.
    pub async fn remove_device(
        &mut self,
        device: &TrustedDevice,
    ) -> Result<()> {
        let urn = device.device_urn()?;
        let device_id = device.public_id()?;
        let key = (*self.keeper.id(), urn);
        if let Some(secret_id) = self.lookup.get(&key) {
            self.keeper.delete(secret_id).await?;
            self.devices.remove(&device_id);
            self.lookup.remove(&key);
        }
        Ok(())
    }

    /// Sign out locking the devices vault.
    pub fn sign_out(&mut self) {
        self.keeper.lock();
    }
}

/// Encapsulates information about a device.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    /// The user's full name.
    pub realname: String,
    /// The user name.
    pub username: String,
    /// The name of the device.
    pub device_name: String,
    /// The hostname or IP address.
    pub hostname: String,
    /// The platform identifier.
    pub platform: whoami::Platform,
    /// The platform distro.
    pub distro: String,
    /// The platform architecture.
    pub arch: whoami::Arch,
    /// The desktop environment.
    pub desktop_env: whoami::DesktopEnv,
}

impl DeviceInfo {
    /// Create new device info.
    pub fn new() -> Self {
        Self {
            realname: whoami::realname(),
            username: whoami::username(),
            device_name: whoami::devicename(),
            hostname: whoami::hostname(),
            platform: whoami::platform(),
            distro: whoami::distro(),
            arch: whoami::arch(),
            desktop_env: whoami::desktop_env(),
        }
    }
}

impl Default for DeviceInfo {
    fn default() -> Self {
        Self::new()
    }
}

/// Additional information about the device such as the
/// device name, manufacturer and model.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct ExtraDeviceInfo {
    #[serde(flatten)]
    info: HashMap<String, Value>,
}

impl fmt::Display for ExtraDeviceInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (o, v) in &self.info {
            if let Value::Object(map) = v {
                for (k, v) in map {
                    if let Value::String(s) = v {
                        writeln!(f, "[{}] {}: {}", o, k, s)?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Device that has been trusted.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedDevice {
    /// Public key of the device.
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
    /// Extra device information.
    pub extra_info: ExtraDeviceInfo,
    /// When this device was trusted.
    pub created_date: OffsetDateTime,
}

impl From<Vec<u8>> for TrustedDevice {
    fn from(value: Vec<u8>) -> Self {
        Self {
            extra_info: Default::default(),
            public_key: value,
            created_date: OffsetDateTime::now_utc(),
        }
    }
}

impl TryFrom<(Vec<u8>, String)> for TrustedDevice {
    type Error = Error;
    fn try_from(value: (Vec<u8>, String)) -> Result<Self> {
        Ok(Self {
            extra_info: serde_json::from_str(&value.1)?,
            public_key: value.0,
            created_date: OffsetDateTime::now_utc(),
        })
    }
}

impl TryFrom<TrustedDevice> for (Vec<u8>, String) {
    type Error = Error;
    fn try_from(value: TrustedDevice) -> Result<Self> {
        Ok((value.public_key, serde_json::to_string(&value.extra_info)?))
    }
}

impl TrustedDevice {
    /// Public identifier derived from the public key (base58 encoded).
    pub fn public_id(&self) -> Result<String> {
        let mut encoded = String::new();
        bs58::encode(&self.public_key).into(&mut encoded)?;
        Ok(encoded)
    }

    /// Get the URN for this device.
    pub fn device_urn(&self) -> Result<Urn> {
        let device_urn =
            format!("urn:sos:{}{}", DEVICES_NSS, self.public_id()?);
        Ok(device_urn.parse()?)
    }
}
