use sos_core::commit_tree::RowInfo;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("path {0} is not a file")]
    NotFile(PathBuf),

    #[error("row checksums do not match at {index}/{total}, expected {commit} but got {value}")]
    HashMismatch {
        index: u32,
        total: u32,
        commit: String,
        value: String,
    },

    #[error(transparent)]
    Core(#[from] sos_core::Error),

    #[error(transparent)]
    Binary(#[from] sos_core::binary_rw::BinaryError),
}
