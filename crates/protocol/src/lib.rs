#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Networking and sync protocol types for the [sos-sdk crate](https://docs.rs/sos-sdk/latest/sos_sdk/).

mod protocol;
pub use protocol::*;

#[cfg(test)]
mod tests;

pub use sos_sdk as sdk;
