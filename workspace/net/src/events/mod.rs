//! Event types for the client and server.

#[cfg(feature = "listen")]
mod change;

#[cfg(feature = "listen")]
pub use change::{ChangeEvent, ChangeNotification};
