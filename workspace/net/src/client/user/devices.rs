//! User device manager.
use crate::client::Result;
use std::path::PathBuf;

#[cfg(feature = "device")]
use crate::device::{self, TrustedDevice};

/// Manages the devices for a user.
#[cfg(feature = "device")]
pub struct DeviceManager {
    device_dir: PathBuf,
}

#[cfg(feature = "device")]
impl DeviceManager {
    /// Create a new devices manager.
    pub(super) fn new(device_dir: PathBuf) -> Result<Self> {
        Ok(Self { device_dir })
    }

    /// Load trusted devices.
    pub async fn load(&self) -> Result<Vec<TrustedDevice>> {
        let devices =
            device::TrustedDevice::load_devices(&self.device_dir).await?;
        let mut trusted = Vec::new();
        for device in devices {
            trusted.push(device);
        }
        Ok(trusted)
    }

    /// Add a trusted device.
    pub async fn add(&mut self, device: TrustedDevice) -> Result<()> {
        device::TrustedDevice::add_device(&self.device_dir, device).await?;
        Ok(())
    }

    /// Remove a trusted device.
    pub async fn remove(&mut self, device: &TrustedDevice) -> Result<()> {
        device::TrustedDevice::remove_device(&self.device_dir, device)
            .await?;
        Ok(())
    }
}
