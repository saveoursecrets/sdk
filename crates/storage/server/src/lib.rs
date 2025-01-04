mod error;

pub mod filesystem;
pub mod server_helpers;
mod storage;
mod traits;

pub use error::Error;
pub use storage::ServerStorage;
pub use traits::ServerAccountStorage;

/// Result type for the server module.
pub type Result<T> = std::result::Result<T, Error>;
