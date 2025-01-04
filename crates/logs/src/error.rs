use thiserror::Error;

/// Errors generated by the log library.
#[derive(Debug, Error)]
pub enum Error {
    /// Errors generated by the core library.
    #[error(transparent)]
    Core(#[from] sos_core::Error),

    /// Errors generated by the IO module.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
