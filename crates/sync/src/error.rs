use thiserror::Error;

/// Errors generated by the library.
#[derive(Debug, Error)]
pub enum Error {
    /// Errors generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),
}
