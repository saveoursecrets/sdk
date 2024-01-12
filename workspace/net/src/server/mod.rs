//! Web server implementation.
mod authenticate;
mod backend;
mod config;
mod error;
mod handlers;
mod server;
mod services;

pub use error::Error;
/// Result type for the server module.
pub type Result<T> = std::result::Result<T, error::Error>;

pub use backend::Backend;
pub use config::*;
pub use server::{
    Server, ServerBackend, ServerInfo, ServerState, ServerTransfer, State,
};
