//! Protocol for pairing devices.
use crate::sdk::device::TrustedDevice;
use serde::{Deserialize, Serialize};

mod enrollment;
mod error;
mod share_url;
mod websocket;

pub use enrollment::DeviceEnrollment;
pub use error::Error;
pub use share_url::ServerPairUrl;
pub use websocket::{AcceptPairing, OfferPairing};

#[deprecated]
pub use enrollment::DeviceShareUrl;

const PATTERN: &str = "Noise_NN_25519_ChaChaPoly_BLAKE2s";

/// Result type for the pairing module.
pub type Result<T> = std::result::Result<T, error::Error>;

/// Pairing message.
#[derive(Debug, Serialize, Deserialize)]
pub(super) enum PairingMessage {
    /// Request sent from the accept side to the
    /// offering side once the noise protocol handshake
    /// has completed.
    Request(TrustedDevice),
    /// Confirmation from the offering side to the
    /// accepting side is the account signing key.
    Confirm([u8; 32]),
    /// Offer side generated an error whilst
    /// adding the device to the list of trusted devices.
    Error(String),
}
