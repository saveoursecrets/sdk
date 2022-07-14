use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("path {0} is not a file")]
    NotFile(PathBuf),

    #[error(transparent)]
    Core(#[from] sos_core::Error),
}
