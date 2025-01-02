mod error;

pub mod filesystem;
pub mod server_helpers;
mod traits;

pub use error::Error;
pub use traits::ServerAccountStorage;

/// Result type for the server module.
pub type Result<T> = std::result::Result<T, Error>;

use async_trait::async_trait;

/// Server storage backed by filesystem or database.
pub enum ServerStorage {
    /// Filesystem storage.
    FileSystem(filesystem::ServerFileStorage),
    /// Database storage (TODO: switch impl).
    Database(filesystem::ServerFileStorage),
}

#[async_trait]
impl ServerAccountStorage for ServerStorage {}
