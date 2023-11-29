//! Types for device support.
use crate::{
    signer::ed25519::{BoxedEd25519Signer, VerifyingKey},
    vault::Summary,
};

/// Encapsulate device specific information for an account.
#[derive(Clone)]
pub struct DeviceSigner {
    /// The vault containing device specific keys.
    pub(crate) summary: Summary,
    /// The signing key for this device.
    pub(crate) signer: BoxedEd25519Signer,
    /// The id of this device; Base58 encoded device public key.
    pub(crate) public_id: String,
}

impl DeviceSigner {
    /// Summary of the vault containing the device
    /// signing key.
    pub fn summary(&self) -> &Summary {
        &self.summary
    }

    /// Device signing key.
    pub fn signer(&self) -> &BoxedEd25519Signer {
        &self.signer
    }

    /// Identifier of the device public key.
    pub fn public_id(&self) -> &str {
        &self.public_id
    }

    /// Get the verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }
}
