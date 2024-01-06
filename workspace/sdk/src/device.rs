//! Types for device support.
use crate::{
    signer::ed25519::{BoxedEd25519Signer, SingleParty, VerifyingKey},
    vault::Gatekeeper,
    Error, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, fmt};
use time::OffsetDateTime;

const DEVICE_PUBLIC_KEY_LEN: usize = 32;

/// Type of a device public key.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct DevicePublicKey(
    #[serde(with = "hex::serde")] [u8; DEVICE_PUBLIC_KEY_LEN],
);

impl DevicePublicKey {
    /// Device public key byte length.
    pub const SIZE: usize = DEVICE_PUBLIC_KEY_LEN;
}

impl hex::FromHex for DevicePublicKey {
    type Error = Error;
    fn from_hex<T: AsRef<[u8]>>(value: T) -> Result<Self> {
        let buf = hex::decode(value)?;
        let buf: [u8; 32] = buf.as_slice().try_into()?;
        Ok(Self(buf))
    }
}

impl From<[u8; 32]> for DevicePublicKey {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<&[u8; 32]> for DevicePublicKey {
    fn from(value: &[u8; 32]) -> Self {
        Self(*value)
    }
}

impl TryFrom<&[u8]> for DevicePublicKey {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        let value: [u8; 32] = value.try_into()?;
        Ok(Self(value))
    }
}

impl TryFrom<&DevicePublicKey> for VerifyingKey {
    type Error = Error;

    fn try_from(value: &DevicePublicKey) -> Result<Self> {
        Ok(VerifyingKey::from_bytes(&value.0)?)
    }
}

impl AsRef<[u8]> for DevicePublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

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

/// Manages the gatekeeper that protects the device signing key.
///
/// Call [DeviceManager::sign_out] to lock the device vault.
pub struct DeviceManager {
    /// Signing key for this device.
    signer: DeviceSigner,
    /// Access to the vault that stores the device
    /// signing key.
    keeper: Gatekeeper,
}

impl DeviceManager {
    /// Create a new device manager.
    ///
    /// The gatekeeper should be unlocked before assigning to a
    /// device manager.
    pub(super) fn new(signer: DeviceSigner, keeper: Gatekeeper) -> Self {
        Self { signer, keeper }
    }

    /// Signing key for this device.
    pub(crate) fn signer(&self) -> &DeviceSigner {
        &self.signer
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
        extra_info: DeviceMetaData,
    ) -> TrustedDevice {
        TrustedDevice::new(
            self.signer.public_key(),
            extra_info,
            OffsetDateTime::now_utc(),
        )
    }

    /// Sign out locking the device vault.
    pub fn sign_out(&mut self) {
        self.keeper.lock();
    }
}

/// Additional information about the device such as the
/// device name, manufacturer and model.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DeviceMetaData {
    #[serde(flatten)]
    info: HashMap<String, Value>,
}

impl Default for DeviceMetaData {
    fn default() -> Self {
        let mut info = HashMap::new();
        info.insert("realname".to_owned(), Value::String(whoami::realname()));
        info.insert("username".to_owned(), Value::String(whoami::username()));
        info.insert(
            "device_name".to_owned(),
            Value::String(whoami::devicename()),
        );
        info.insert("hostname".to_owned(), Value::String(whoami::hostname()));
        info.insert(
            "platform".to_owned(),
            Value::String(whoami::platform().to_string()),
        );
        info.insert("distro".to_owned(), Value::String(whoami::distro()));
        info.insert(
            "arch".to_owned(),
            Value::String(whoami::arch().to_string()),
        );
        info.insert(
            "desktop".to_owned(),
            Value::String(whoami::desktop_env().to_string()),
        );
        Self { info }
    }
}

impl fmt::Display for DeviceMetaData {
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
#[derive(Debug, Clone, Serialize, Deserialize, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrustedDevice {
    /// Public key of the device.
    public_key: DevicePublicKey,
    /// Extra device information.
    extra_info: DeviceMetaData,
    /// When this device was trusted.
    created_date: OffsetDateTime,
}

impl PartialEq for TrustedDevice {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl TrustedDevice {
    /// Create a new trusted device.
    pub fn new(
        public_key: DevicePublicKey,
        extra_info: DeviceMetaData,
        created_date: OffsetDateTime,
    ) -> Self {
        Self {
            public_key,
            extra_info,
            created_date,
        }
    }

    /// Device public key.
    pub fn public_key(&self) -> &DevicePublicKey {
        &self.public_key
    }

    /// Public identifier derived from the public key (base58 encoded).
    pub fn public_id(&self) -> Result<String> {
        let mut encoded = String::new();
        bs58::encode(&self.public_key).into(&mut encoded)?;
        Ok(encoded)
    }

    /// Extra device information.
    pub fn extra_info(&self) -> &DeviceMetaData {
        &self.extra_info
    }

    /// Date and time this trusted device was created.
    pub fn created_date(&self) -> &OffsetDateTime {
        &self.created_date
    }
}

impl From<DevicePublicKey> for TrustedDevice {
    fn from(value: DevicePublicKey) -> Self {
        Self {
            extra_info: Default::default(),
            public_key: value,
            created_date: OffsetDateTime::now_utc(),
        }
    }
}

impl TryFrom<&TrustedDevice> for (DevicePublicKey, String) {
    type Error = Error;
    fn try_from(value: &TrustedDevice) -> Result<Self> {
        Ok((
            value.public_key.clone(),
            serde_json::to_string(&value.extra_info)?,
        ))
    }
}
