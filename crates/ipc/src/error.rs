use crate::IpcResponseError;
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
    MessageId(u32, u32),

    /// Error when a response type does not match the request type.
    #[error("response type does not match the request type")]
    ResponseType,

    /// Error response received from a server.
    #[error("{1:?} (id={0})")]
    ResponseError(u32, IpcResponseError),

    /// Service request timed out.
    #[error("service request timed out, exceeded duration {0:?}")]
    ServiceTimeout(Duration),

    /// Error when the native bridge denies proxying due to an
    /// invalid extension identifier.
    #[cfg(feature = "native-bridge")]
    #[error("extension denied: {0}")]
    NativeBridgeDenied(String),

    /// Error when the native bridge fails to send a proxy
    /// request via the IPC client socket.
    #[cfg(feature = "native-bridge")]
    #[error("native bridge failed to send IPC proxy request, reason: {0}")]
    NativeBridgeClientProxy(String),

    /// Error when the native bridge fails to parse the incoming
    /// request JSON.
    #[cfg(feature = "native-bridge")]
    #[error("native bridge failed to parse JSON, reason: {0}")]
    NativeBridgeJsonParse(String),

    /// Error generated by the protobuf library when encoding.
    #[error(transparent)]
    ProtoBufEncode(#[from] prost::EncodeError),

    /// Error generated by the protobuf library when decoding.
    #[error(transparent)]
    ProtoBufDecode(#[from] prost::DecodeError),

    /// Error generated by the protobuf library when converting enums.
    #[error(transparent)]
    ProtoEnum(#[from] prost::UnknownEnumValue),

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
    Sdk(#[from] sos_net::sdk::Error),

    /// Errors generated by the networking library.
    #[error(transparent)]
    Net(#[from] sos_net::Error),

    /// Errors generated by the account extras library.
    #[error(transparent)]
    AccountExtras(#[from] sos_account_extras::Error),

    /// Errors generated by the protocol library.
    #[error(transparent)]
    Protocol(#[from] sos_net::protocol::Error),

    /// Errors generated when a URI is invalid.
    #[error(transparent)]
    HttpUri(#[from] http::uri::InvalidUri),

    /// Errors generated when a HTTP method is invalid.
    #[error(transparent)]
    HttpMethod(#[from] http::method::InvalidMethod),

    /// Errors generated when a HTTP status code is invalid.
    #[error(transparent)]
    HttpStatus(#[from] http::status::InvalidStatusCode),

    /// Errors generated from network responses.
    #[error(transparent)]
    Network(#[from] sos_protocol::NetworkError),
}

impl From<Error> for IpcResponseError {
    fn from(value: Error) -> Self {
        let code = match &value {
            Error::ServiceTimeout(_) => 504, // Gateway timeout
            #[cfg(feature = "native-bridge")]
            Error::NativeBridgeDenied(_) => 403, // Forbidden
            #[cfg(feature = "native-bridge")]
            Error::NativeBridgeClientProxy(_) => 502, // Bad gateway
            #[cfg(feature = "native-bridge")]
            Error::NativeBridgeJsonParse(_) => 400, // Bad request
            _ => -1,
        };
        IpcResponseError {
            code,
            message: value.to_string(),
        }
    }
}
