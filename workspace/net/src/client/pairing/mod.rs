//! Protocol for pairing devices.
use serde::{Serialize, Deserialize};
use crate::sdk::device::TrustedDevice;

mod error;
mod share_url;
mod websocket;

pub use error::Error;
pub use share_url::ServerPairUrl;
pub use websocket::{Accept, Offer, WebSocketPairAccept, WebSocketPairOffer};

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Result type for the pairing module.
pub type Result<T> = std::result::Result<T, error::Error>;

/// Pairing message.
#[derive(Serialize, Deserialize)]
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

