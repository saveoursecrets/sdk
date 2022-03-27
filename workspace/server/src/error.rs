use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum Error {
    #[error("not a directory {0}")]
    NotDirectory(PathBuf),

    #[error("no vaults found")]
    NoVaults,

    #[error("vault {0} does not exist")]
    NotExist(Uuid),

    #[error(transparent)]
    Core(#[from] sos_core::Error),

    //#[error(transparent)]
    //Backend(#[from] crate::backend::BackendError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    TomlDeser(#[from] toml::de::Error),

    #[error(transparent)]
    AddrParse(#[from] std::net::AddrParseError),
}
