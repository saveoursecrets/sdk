//! Web server implementation.
mod authenticate;
mod backend;
mod config;
mod error;
mod handlers;
mod server;
mod services;
mod transports;

pub use error::Error;
/// Result type for the server module.
pub type Result<T> = std::result::Result<T, error::Error>;

pub use backend::{Backend, BackendHandler, FileSystemBackend};
pub use config::*;
pub use server::{Server, ServerInfo, State};
pub use transports::{TransportChannel, TransportManager};
