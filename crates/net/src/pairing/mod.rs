//! Protocol for pairing devices.
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
