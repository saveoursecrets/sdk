use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0} is not a file")]
    NotFile(PathBuf),

    /// Error generated when a file is empty.
    #[error("file {0} is empty")]
    EmptyFile(PathBuf),

    /// Error generated when a file is less than the size of the identity bytes.
    #[error("file {0} is too small, need at least {1} bytes")]
    FileTooSmall(PathBuf, usize),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Core(#[from] sos_core::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    SerdeBinary(#[from] sos_core::serde_binary::Error),

    #[error(transparent)]
    Binary(#[from] sos_core::serde_binary::binary_rw::BinaryError),
}
