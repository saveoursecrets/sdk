#![deny(missing_docs)]
//! Library for client and server communication.
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod server;
mod sync;

pub use sync::*;
