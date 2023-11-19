//! Traits and implementations for clients.

#[cfg(not(target_arch = "wasm32"))]
mod changes_listener;
#[cfg(feature = "hashcheck")]
pub mod hashcheck;
pub mod net;
mod sync;
mod user;

mod error;

#[cfg(not(target_arch = "wasm32"))]
pub use changes_listener::ChangesListener;
pub use error::Error;

pub use sync::RemoteSync;
pub use user::*;

/// Result type for the client module.
pub type Result<T> = std::result::Result<T, error::Error>;
