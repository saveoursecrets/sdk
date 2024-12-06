use thiserror::Error;
use tokio::time::Duration;

/// Error type for the library.
#[derive(Error, Debug)]
pub enum Error {
    /// Error reading server response.
    #[error("no server response")]
    NoResponse,

    /// Error decoding a request.
    #[error("error decoding ipc request")]
    DecodeRequest,

    /// Error decoding a response.
    #[error("error decoding ipc response")]
    DecodeResponse,

    /// Error when a response message id does not match the request id.
    #[error("response id {1} does not match request id {0}")]
    MessageId(u64, u64),

    /// Error when a response type does not match the request type.
    #[error("response type does not match the request type")]
    ResponseType,

    /// Service request timed out.
    #[error("service request timed out, exceeded duration {0:?}")]
    ServiceTimeout(Duration),

    /// Error when the native bridge fails to send a proxy
    /// request via the IPC client socket.
    #[cfg(feature = "native-bridge-server")]
    #[error("native bridge failed to send request, reason: {0}")]
    NativeBridgeClientProxy(String),

    /// Error when the native bridge fails to parse the incoming
    /// request JSON.
    #[cfg(feature = "native-bridge-server")]
    #[error("native bridge failed to parse JSON, reason: {0}")]
    NativeBridgeJsonParse(String),

    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Errors generated converting integers.
    #[error(transparent)]
    Int(#[from] std::num::TryFromIntError),

    /// Errors generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Errors generated by the system time.
    #[error(transparent)]
    SystemTime(#[from] std::time::SystemTimeError),

    /// Errors generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] sos_sdk::Error),

    /// Errors generated by the protocol library.
    #[error(transparent)]
    Protocol(#[from] sos_protocol::Error),

    /// Errors generated when a URI is invalid.
    #[error(transparent)]
    HttpUri(#[from] http::uri::InvalidUri),

    /// Errors generated when a HTTP method is invalid.
    #[error(transparent)]
    HttpMethod(#[from] http::method::InvalidMethod),

    /// Errors generated when a HTTP status code is invalid.
    #[error(transparent)]
    HttpStatus(#[from] http::status::InvalidStatusCode),

    /// Errors generated by the hyper library.
    #[error(transparent)]
    Hyper(#[from] hyper::Error),

    /// Errors generated from network responses.
    #[error(transparent)]
    Network(#[from] sos_protocol::NetworkError),
}
