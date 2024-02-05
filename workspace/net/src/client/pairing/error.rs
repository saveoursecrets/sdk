//! Error type for the pairing module.
use crate::sdk::sync::SyncError;
use thiserror::Error;

/// Errors generated by the pairing library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated trying to parse a pairing URL.
    #[error("invalid pairing url")]
    InvalidShareUrl,

    /// Error generated if a packet has a to public key that does not
    /// match the recipient key pair.
    #[error("packet public key is not for me")]
    NotForMe,

    /// Error generated failing to sync devices patch.
    #[error("failed to sync devices: {0}")]
    DevicePatchSync(SyncError<crate::client::Error>),

    /// Error generated trying to access device enrollment
    /// before pairing protocol completion.
    #[error("enrollment is not available")]
    NoEnrollment,

    /// Error generated when the protocol is in the wrong state
    /// or a packet payload is not of the expected type.
    #[error("pairing protocol bad state or invalid packet payload")]
    BadState,

    /// Error generated by the client library.
    #[error(transparent)]
    Client(#[from] crate::client::Error),

    /// Error generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] crate::sdk::Error),

    /// Error generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error generated when parsing from hex.
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    /// Error generated attempting to convert from a slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated attempting to parse a URL.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),

    /// Error generated by the snow noise protocol library.
    #[error(transparent)]
    Snow(#[from] snow::Error),

    /// Error generated by the websocket client.
    #[error(transparent)]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
}
