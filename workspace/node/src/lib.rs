#![deny(missing_docs)]
//! Library for network communication.
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod server;
pub mod sync;
