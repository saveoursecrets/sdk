mod error;
mod preferences;

pub use error::Error;
pub use preferences::*;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;

