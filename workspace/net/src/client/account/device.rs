//! Account device manager.
use crate::{
    client::{NetworkAccount, Result},
    sdk::account::device::DeviceManager,
};

impl NetworkAccount {
    /// Account devices reference.
    pub fn devices(&self) -> Result<&DeviceManager> {
        Ok(self.account.devices()?)
    }

    /// Account devices mutable reference.
    pub fn devices_mut(&mut self) -> Result<&mut DeviceManager> {
        Ok(self.account.devices_mut()?)
    }
}
