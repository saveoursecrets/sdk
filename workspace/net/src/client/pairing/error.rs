//! Error type for the pairing module.
use thiserror::Error;

/// Errors generated by the pairing library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated trying to parse a pairing URL.
    #[error("invalid pairing url")]
    InvalidShareUrl,

    /// Error generated by the client library.
    #[error(transparent)]
    Client(#[from] crate::client::Error),

    /// Error generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error generated when parsing from hex.
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

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
