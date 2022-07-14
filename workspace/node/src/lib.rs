#![deny(missing_docs)]
//! Library for client and server communication.
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "server")]
pub mod server;
mod sync;

#[cfg(feature = "client")]
pub use client::{run_blocking, ClientBuilder, PassphraseReader};

pub use sync::*;
