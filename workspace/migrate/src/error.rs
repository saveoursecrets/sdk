//! Error type for the library.
use thiserror::Error;

/// Error type for the migration library.
#[derive(Debug, Error)]
pub enum Error {
    /// Error generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_sdk::Error),

    /// Error generated by the keychain access integration.
    #[cfg(target_os = "macos")]
    #[error(transparent)]
    Keychain(#[from] crate::import::keychain::Error),

    /// Error generated by the io module.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Error generated by the csv library.
    #[error(transparent)]
    Csv(#[from] csv::Error),

    /// Error generated by the zip library.
    #[error(transparent)]
    Zip(#[from] zip::result::ZipError),
}
