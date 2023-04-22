//! Traits and implementations for clients.

#[cfg(not(target_arch = "wasm32"))]
use std::future::Future;

#[cfg(not(target_arch = "wasm32"))]
pub mod account_manager;
#[cfg(not(target_arch = "wasm32"))]
mod changes_listener;
pub mod net;
pub mod provider;

mod error;

#[cfg(not(target_arch = "wasm32"))]
pub use changes_listener::ChangesListener;
pub use error::Error;

/// Result type for the client module.
pub type Result<T> = std::result::Result<T, error::Error>;
