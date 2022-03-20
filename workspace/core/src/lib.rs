#![deny(missing_docs)]
//! Secret storage manager.

pub mod address;
pub mod client;
pub mod crypto;
pub mod passphrase;
pub mod service;
pub mod traits;
pub mod vault;

pub use vault::{into_encoded_buffer, from_encoded_buffer};
