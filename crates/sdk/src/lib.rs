#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

pub mod device;
pub mod prelude;

pub use sos_core::events;
pub use sos_core::Paths;
pub use sos_core::{decode, encode};

// Deprecated re-exports for backwards compatibility
// DO NOT USE - some will be removed in the future
pub use sos_core::constants;
pub use sos_core::crypto;
pub use sos_core::UtcDateTime;
pub use sos_login as identity;
pub use sos_vault as vault;
pub use sos_vfs as vfs;
