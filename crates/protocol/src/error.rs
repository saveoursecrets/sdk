//! Error type for the wire protocol.
use crate::{MaybeConflict, SyncStatus};
use http::StatusCode;
use serde_json::Value;
use sos_sdk::time;
use thiserror::Error;

/// Trait for error implementations that
/// support a conflict error.
pub trait AsConflict {
    /// Determine if this is a conflict error.
    fn is_conflict(&self) -> bool;

    /// Determine if this is a hard conflict error.
    fn is_hard_conflict(&self) -> bool;

    /// Take an underlying conflict error.
    fn take_conflict(self) -> Option<ConflictError>;
}

/// Errors generated by the wire protocol.
#[derive(Debug, Error)]
pub enum Error {
    /// Reached EOF decoding a relay packet.
    #[error("relay packet end of file")]
    EndOfFile,

    /// Generic boxed error.
    #[error(transparent)]
    Boxed(#[from] Box<dyn std::error::Error + Send + Sync>),

    /// Error generated when a conflict is detected.
    #[error(transparent)]
    Conflict(#[from] ConflictError),

    /// Error generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated converting from a slice.
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    /// Error generated by the protobuf library when encoding.
    #[error(transparent)]
    ProtoBufEncode(#[from] prost::EncodeError),

    /// Error generated by the protobuf library when decoding.
    #[error(transparent)]
    ProtoBufDecode(#[from] prost::DecodeError),

    /// Error generated by the protobuf library when converting enums.
    #[error(transparent)]
    ProtoEnum(#[from] prost::UnknownEnumValue),

    /// Error generated by the SDK library.
    #[error(transparent)]
    Sdk(#[from] crate::sdk::Error),

    /// Error generated by the merkle tree library.
    #[error(transparent)]
    Merkle(#[from] rs_merkle::Error),

    /// Error generated converting time types.
    #[error(transparent)]
    Time(#[from] time::error::ComponentRange),

    /// Error generated joining a task.
    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),

    /// Error generated parsing URLs.
    #[error(transparent)]
    UrlParse(#[from] crate::sdk::url::ParseError),

    /// Error generated by the HTTP library.
    #[error(transparent)]
    Http(#[from] http::Error),

    /// Error generated by the HTTP library.
    #[error(transparent)]
    StatusCode(#[from] http::status::InvalidStatusCode),

    /// Error generated by the JSON library.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// Error generated by network communication.
    #[error(transparent)]
    Network(#[from] NetworkError),
}

/// Error created communicating over the network.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Error generated when an unexpected response code is received.
    #[error("unexpected response status code {0}")]
    ResponseCode(StatusCode),

    /// Error generated when an unexpected response code is received.
    #[error("unexpected response {1} (code: {0})")]
    ResponseJson(StatusCode, Value),

    /// Error generated when an unexpected content type is returend.
    #[error("unexpected content type {0}, expected: {1}")]
    ContentType(String, String),
}

/// Error created whan a conflict is detected.
#[derive(Debug, Error)]
pub enum ConflictError {
    /// Error generated when a soft conflict was detected.
    ///
    /// A soft conflict may be resolved by searching for a
    /// common ancestor commit and merging changes since
    /// the common ancestor commit.
    #[error("soft conflict")]
    Soft {
        /// Conflict information.
        conflict: MaybeConflict,
        /// Local information sent to the remote.
        local: SyncStatus,
        /// Remote information in the server reply.
        remote: SyncStatus,
    },

    /// Error generated when a hard conflict was detected.
    ///
    /// A hard conflict is triggered after a soft conflict
    /// attempted to scan proofs on a remote and was unable
    /// to find a common ancestor commit.
    #[error("hard conflict")]
    Hard,
}

impl AsConflict for Error {
    fn is_conflict(&self) -> bool {
        matches!(self, Error::Conflict(_))
    }

    fn is_hard_conflict(&self) -> bool {
        matches!(self, Error::Conflict(ConflictError::Hard))
    }

    fn take_conflict(self) -> Option<ConflictError> {
        match self {
            Self::Conflict(err) => Some(err),
            _ => None,
        }
    }
}
