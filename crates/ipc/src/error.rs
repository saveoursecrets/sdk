use thiserror::Error;

/// Error type for the library.
#[derive(Error, Debug)]
pub enum Error {
    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Errors generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Errors generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] sos_sdk::Error),

    /// Errors generated by the protocol library.
    #[error(transparent)]
    Protocol(#[from] sos_protocol::Error),

    /// Errors generated when a URI is invalid.
    #[error(transparent)]
    HttpUri(#[from] http::uri::InvalidUri),

    /// Errors generated by the hyper library.
    #[cfg(any(feature = "client", feature = "server"))]
    #[error(transparent)]
    Hyper(#[from] hyper::Error),

    /// Errors generated from network responses.
    #[error(transparent)]
    Network(#[from] sos_protocol::NetworkError),
}
