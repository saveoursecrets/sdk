use std::path::PathBuf;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not a directory {0}")]
    NotDirectory(PathBuf),

    #[error("no vaults found")]
    NoVaults,

    #[error("vault {0} does not exist")]
    NotExist(Uuid),

    #[error("url scheme {0} is not supported")]
    InvalidUrlScheme(String),

    #[error("url {0} is not a valid file path")]
    UrlFilePath(Url),

    #[error(transparent)]
    Core(#[from] sos_core::Error),

    #[error(transparent)]
    Url(#[from] url::ParseError),

    #[error(transparent)]
    HeaderValue(#[from] axum::http::header::InvalidHeaderValue),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    TomlDeser(#[from] toml::de::Error),

    #[error(transparent)]
    AddrParse(#[from] std::net::AddrParseError),
}
