use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0} is not a file")]
    NotFile(PathBuf),

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
