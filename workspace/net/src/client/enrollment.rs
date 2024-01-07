//! Enroll a device to an account on a remote server.

use std::path::PathBuf;
use crate::{
    client::{Origin, Result, net::RpcClient},
    sdk::{signer::ecdsa::BoxedEcdsaSigner, device::DeviceSigner, Paths},
};

/// Enroll a device to a remote server account.
pub struct DeviceEnrollment {
    /// Origin server.
    origin: Origin,
    /// Account paths.
    paths: Paths,
    /// Account signing key.
    account_signing_key: BoxedEcdsaSigner,
    /// Device signing key.
    device_signing_key: DeviceSigner,
}

impl DeviceEnrollment {
    /// Create a new device enrollment.
    pub fn new(
        origin: Origin,
        account_signing_key: BoxedEcdsaSigner,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let address = account_signing_key.address()?;

        let data_dir = if let Some(data_dir) = &data_dir {
            data_dir.clone()
        } else {
            Paths::data_dir()?
        };
        let paths = Paths::new(data_dir, address.to_string());

        Ok(Self {
            origin,
            paths,
            account_signing_key,
            device_signing_key: DeviceSigner::new_random(),
        })
    }
    
    /// Enroll to an account on the remote origin.
    pub async fn enroll(&self) -> Result<()> {
        todo!("perform device enrollment");
        //Ok(())
    }
}
