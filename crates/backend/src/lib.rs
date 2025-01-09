pub mod compact;
mod error;
pub mod folder;
pub mod reducers;

pub use error::Error;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
