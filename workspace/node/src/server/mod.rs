//! Web server implementation.
#[cfg(feature = "gui")]
mod assets;
mod authenticate;
mod backend;
mod config;
mod error;
mod handlers;
mod headers;
mod server;
mod services;

pub use error::Error;
/// Result type for the server module.
pub type Result<T> = std::result::Result<T, error::Error>;

pub use backend::{Backend, FileSystemBackend};
pub use config::*;
pub use server::{Server, ServerInfo, State};
