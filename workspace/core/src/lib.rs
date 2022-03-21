#![deny(missing_docs)]
//! Secret storage manager.

pub mod address;
pub mod client;
pub mod crypto;
pub mod gatekeeper;
pub mod passphrase;
pub mod secret;
pub mod service;
pub mod traits;
pub mod vault;

pub use vault::{from_encoded_buffer, into_encoded_buffer};
