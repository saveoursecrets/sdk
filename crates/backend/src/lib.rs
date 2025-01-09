mod error;

pub use error::Error;
pub mod reducers;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
