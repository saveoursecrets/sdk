//! Protocol for pairing devices.
mod error;
mod packet;
mod share_url;
mod websocket;

pub use error::Error;
pub use share_url::ServerPairUrl;
pub use websocket::{WebSocketPairAccept, WebSocketPairOffer};

const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Result type for the pairing module.
pub type Result<T> = std::result::Result<T, error::Error>;
