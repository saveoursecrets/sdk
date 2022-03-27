mod assets;
mod backend;
mod config;
mod error;
mod server;

pub type Result<T> = std::result::Result<T, error::Error>;

pub use backend::{Backend, FileSystemBackend};
pub use config::ServerConfig;
pub use error::Error;
pub use server::{Server, State};
