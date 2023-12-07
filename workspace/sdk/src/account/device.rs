//! Expose the device manager on an account.
use crate::{account::Account, device::DeviceManager, Error, Result};

impl<D> Account<D> {
    /// Devices reference.
    pub fn devices(&self) -> Result<&DeviceManager> {
        self.authenticated
            .as_ref()
            .map(|a| &a.devices)
            .ok_or(Error::NotAuthenticated)
    }

    /// Devices mutable reference.
    pub fn devices_mut(&mut self) -> Result<&mut DeviceManager> {
        self.authenticated
            .as_mut()
            .map(|a| &mut a.devices)
            .ok_or(Error::NotAuthenticated)
    }
}
