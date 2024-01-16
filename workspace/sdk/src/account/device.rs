//! Expose the device manager on an account.
use crate::{account::LocalAccount, device::DeviceManager, Error, Result};

impl LocalAccount {
    /// Device manager.
    pub fn devices(&self) -> Result<&DeviceManager> {
        self.authenticated
            .as_ref()
            .ok_or(Error::NotAuthenticated)?
            .user
            .devices()
    }
}
