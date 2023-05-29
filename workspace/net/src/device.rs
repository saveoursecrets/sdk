//! Functions for getting the local LAN IP address and
//! information about the device.
use if_addrs::{get_if_addrs, IfAddr, Ifv4Addr};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    fmt,
    path::{Path, PathBuf},
};

use sos_sdk::{
    time::OffsetDateTime,
    vfs::{self, File},
};

use crate::{Error, Result};

/// Get v4 IP addresses that are not the loopback or link
/// local addresses.
pub fn v4_lan_ip_list() -> Result<Vec<Ifv4Addr>> {
    let addrs = get_if_addrs()?;
    let mut output = Vec::with_capacity(addrs.len());
    for net in addrs {
        if let IfAddr::V4(v4) = net.addr {
            if v4.is_loopback() || v4.is_link_local() {
                continue;
            }
            output.push(v4);
        }
    }
    Ok(output)
}

/// Get the first v4 IP address that is not a loopback
/// or link local address.
pub fn v4_lan_ip() -> Result<Option<Ifv4Addr>> {
    let mut ips = v4_lan_ip_list()?;
    Ok(if !ips.is_empty() {
        Some(ips.remove(0))
    } else {
        None
    })
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

#[derive(Default, Clone, Serialize, Deserialize)]
/// Additional information about the device such as the
/// device name, manufacturer and model.
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
    /// The public key for the device.
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
    /// Compute a base58 address string of this public key.
    pub fn address(&self) -> Result<String> {
        let mut encoded = String::new();
        bs58::encode(&self.public_key).into(&mut encoded)?;
        Ok(encoded)
    }

    /// Add a device to the trusted devices for an account.
    ///
    /// If a device already exists it is overwritten.
    pub async fn add_device<P: AsRef<Path>>(
        device_dir: P,
        device: TrustedDevice,
    ) -> Result<()> {
        let device_path = Self::device_path(device_dir, &device).await?;
        let json = serde_json::to_vec_pretty(&device)?;
        vfs::write(&device_path, &json).await?;
        Ok(())
    }

    /// Remove a device from the trusted devices for an account.
    pub async fn remove_device<P: AsRef<Path>>(
        device_dir: P,
        device: &TrustedDevice,
    ) -> Result<()> {
        let device_path = Self::device_path(device_dir, device).await?;
        vfs::remove_file(device_path).await?;
        Ok(())
    }

    /// Load all trusted devices for an account.
    pub async fn load_devices<P: AsRef<Path>>(
        device_dir: P,
    ) -> Result<Vec<TrustedDevice>> {
        let mut devices = Vec::new();
        if !device_dir.as_ref().exists() {
            vfs::create_dir_all(device_dir.as_ref()).await?;
        }

        let mut dir = vfs::read_dir(device_dir.as_ref()).await?;
        while let Some(entry) = dir.next_entry().await? {
            let buffer = vfs::read(entry.path()).await?;
            let device: TrustedDevice = serde_json::from_slice(&buffer)?;
            devices.push(device);
        }
        Ok(devices)
    }

    async fn device_path<P: AsRef<Path>>(
        device_dir: P,
        device: &TrustedDevice,
    ) -> Result<PathBuf> {
        let device_address = device.address()?;
        let mut device_path = device_dir.as_ref().join(device_address);
        device_path.set_extension("json");
        if let Some(parent) = device_path.parent() {
            if !parent.exists() {
                vfs::create_dir_all(parent).await?;
            }
        }
        Ok(device_path)
    }
}
