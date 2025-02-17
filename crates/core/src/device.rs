//! Types for device support.
use crate::{Error, Result};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fmt,
    hash::{Hash, Hasher},
};
use time::OffsetDateTime;

/// Device meta data.
///
/// Applications can set this when they boot so that trusted devices
/// will prefer this meta data.
pub static DEVICE: OnceCell<DeviceMetaData> = OnceCell::new();

/// Type of a device public key.
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct DevicePublicKey(
    #[serde(with = "hex::serde")] [u8; DevicePublicKey::SIZE],
);

impl DevicePublicKey {
    /// Device public key length.
    pub const SIZE: usize = 32;
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

impl AsRef<[u8]> for DevicePublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for DevicePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Additional information about the device such as the
/// device name, manufacturer and model.
#[derive(Default, Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DeviceMetaData {
    // Note that order is very important here as this type
    // is included in the device event log and if the order
    // is non-deterministic the commit hashes will differ.
    #[serde(flatten)]
    info: BTreeMap<String, Value>,
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

impl Hash for TrustedDevice {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.public_key.as_ref().hash(state);
    }
}

impl TrustedDevice {
    /// Create a new trusted device.
    pub fn new(
        public_key: DevicePublicKey,
        extra_info: Option<DeviceMetaData>,
        created_date: Option<OffsetDateTime>,
    ) -> Self {
        let extra_info = if let Some(extra_info) = extra_info {
            extra_info
        } else {
            if let Some(device) = DEVICE.get() {
                device.clone()
            } else {
                Default::default()
            }
        };

        Self {
            public_key,
            extra_info,
            created_date: created_date
                .unwrap_or_else(|| OffsetDateTime::now_utc()),
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
