mod error;

pub mod filesystem;

pub use error::Error;

/// Result type for the server module.
pub type Result<T> = std::result::Result<T, Error>;
