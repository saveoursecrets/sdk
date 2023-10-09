//! Errors generated by the library.
use thiserror::Error;

/// Error generated by the artifact library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error when a platform is invalid.
    #[error("unknown platform '{0}'")]
    UnknownPlatform(String),

    /// Error when a processor architecture is unknown.
    #[error("unknown architecture '{0}'")]
    UnknownArch(String),

    /// Error when a distro is invalid.
    #[error("unknown distribution '{0}'")]
    UnknownDistro(String),

    /// Error when a distribution collection is invalid.
    ///
    /// Supported values are currently `gui` and `cli`.
    #[error("unknown collection '{0}'")]
    UnknownCollection(String),
    
    /// Error when a distribution channel is invalid.
    #[error("unknown distribution channel '{0}'")]
    UnknownChannel(String),

    /// Error when a platform variant is invalid.
    #[error("unknown platform variant '{0}'")]
    UnknownVariant(String),
}
