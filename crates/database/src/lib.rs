mod error;
pub mod migrations;

pub use error::Error;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;
