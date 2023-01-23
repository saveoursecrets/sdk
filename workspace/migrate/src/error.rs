//! Error type for the library.
use thiserror::Error;

/// Error type for the migration library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated if the name for a keychain could not
    /// be determined, no file stem.
    #[error("could not determine name for a keychain")]
    NoKeychainName,

    /// Error generated by the io library.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated by the utf8 conversion.
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    /// Error generated by the security framework.
    #[cfg(target_os = "macos")]
    #[error(transparent)]
    SecurityFramework(#[from] security_framework::base::Error),

    /// Error generated by the mpsc sender.
    #[error(transparent)]
    SendBool(#[from] std::sync::mpsc::SendError<bool>),
}
