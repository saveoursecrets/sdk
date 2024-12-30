pub mod db;
mod error;
pub mod importer;
pub mod migrations;
pub mod storage;

pub use error::Error;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;
