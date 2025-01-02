mod error;

pub mod filesystem;
pub mod server_helpers;
mod traits;

pub use error::Error;
pub use traits::ServerStorage;

/// Result type for the server module.
pub type Result<T> = std::result::Result<T, Error>;
