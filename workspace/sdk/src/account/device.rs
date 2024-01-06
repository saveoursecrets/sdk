//! Expose the device manager on an account.
use crate::{account::Account, device::DeviceManager, Error, Result};

impl Account {
    /// Devices reference.
    pub fn devices(&self) -> Result<&DeviceManager> {
        self.authenticated
            .as_ref()
            .ok_or(Error::NotAuthenticated)?
            .user
            .devices()
    }
}
