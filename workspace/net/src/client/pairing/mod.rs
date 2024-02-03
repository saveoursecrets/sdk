//! Protocol for pairing devices.
mod error;
mod share_url;
mod websocket;

pub use error::Error;
pub use share_url::ServerPairUrl;
pub use websocket::{WebSocketPairOffer, WebSocketPairAccept};

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Result type for the pairing module.
pub type Result<T> = std::result::Result<T, error::Error>;
