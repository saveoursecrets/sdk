//! Traits and implementations for clients.

#[cfg(not(target_arch = "wasm32"))]
mod changes_listener;
pub mod hashcheck;
pub mod net;
pub mod provider;
mod sync;
pub mod user;

mod error;

#[cfg(not(target_arch = "wasm32"))]
pub use changes_listener::ChangesListener;
pub use error::Error;

pub use sync::RemoteSync;

/// Result type for the client module.
pub type Result<T> = std::result::Result<T, error::Error>;
