use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("file {0} is not a directory")]
    NotDirectory(PathBuf),

    #[error("file {0} already exists")]
    FileExists(PathBuf),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Keystore(#[from] web3_keystore::KeyStoreError),

    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),

    #[error(transparent)]
    Core(#[from] sos_core::Error),

    #[error(transparent)]
    Readline(#[from] sos_readline::Error),

    #[error(transparent)]
    Http(#[from] reqwest::Error),

    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
}
