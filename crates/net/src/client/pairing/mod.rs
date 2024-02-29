//! Protocol for pairing devices.
use crate::sdk::device::DeviceMetaData;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, serde_as};

mod enrollment;
mod error;
mod share_url;
mod websocket;

pub use enrollment::DeviceEnrollment;
pub use error::Error;
pub use share_url::ServerPairUrl;
pub use websocket::{AcceptPairing, OfferPairing};

/// Result type for the pairing module.
pub type Result<T> = std::result::Result<T, error::Error>;

/// Pairing message.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum PairingMessage {
    /// Indicates the noise protocol handshake is completed.
    Ready,
    /// Request sent from the accept side to the
    /// offering side once the noise protocol handshake
    /// has completed.
    Request(DeviceMetaData),
    /// Confirmation from the offering side to the
    /// accepting side is the account signing key.
    Confirm(PairingConfirmation),
    /// Offer side generated an error whilst
    /// adding the device to the list of trusted devices.
    Error(String),
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct PairingConfirmation(
    /// Account signing key.
    #[serde_as(as = "Base64")]
    [u8; 32],
    /// Device signing key.
    #[serde_as(as = "Base64")]
    [u8; 32],
    /// Encoded device vault.
    #[serde_as(as = "Base64")]
    Vec<u8>,
);
