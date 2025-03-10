//! Local socket change notification producer and consumer.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

#[cfg(any(feature = "changes-producer", feature = "changes-consumer"))]
mod error;

#[cfg(any(feature = "changes-producer", feature = "changes-consumer"))]
pub use error::Error;

#[cfg(feature = "changes-consumer")]
pub mod consumer;
#[cfg(feature = "changes-producer")]
pub mod producer;
