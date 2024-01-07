//! Enroll a device to an account on a remote server.

use crate::{
    client::{net::RpcClient, Origin, Result, Error},
    sdk::{device::DeviceSigner, signer::ecdsa::Address, Paths, sync::Client},
};
use std::path::PathBuf;

/// Enroll a device to a remote server account.
pub struct DeviceEnrollment {
    /// Account paths.
    paths: Paths,
    /// Account address.
    address: Address,
    /// Device signing key.
    pub(crate) device_signing_key: DeviceSigner,
}

impl DeviceEnrollment {
    /// Create a new device enrollment.
    pub fn new(
        address: Address,
        data_dir: Option<PathBuf>,
    ) -> Result<Self> {
        let data_dir = if let Some(data_dir) = &data_dir {
            data_dir.clone()
        } else {
            Paths::data_dir()?
        };
        let paths = Paths::new(data_dir, address.to_string());

        Ok(Self {
            paths,
            address,
            device_signing_key: DeviceSigner::new_random(),
        })
    }

    /// Enroll this device to an account using the given client.
    pub async fn enroll(&self, client: impl Client) -> Result<()> {
        self.paths.ensure().await?;

        match client.fetch_account().await {
            Ok(change_set) => {
                todo!("perform device enrollment");
            }
            Err(e) => {
                Err(Error::EnrollFetch(client.url().to_string()))
            }
        }
    }
}
