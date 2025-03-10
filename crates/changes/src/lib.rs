//! Local socket change notification producer and consumer.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod error;

pub use error::Error;
use sos_core::{commit::CommitSpan, events::EventLogType, AccountId};

#[cfg(feature = "changes-consumer")]
pub mod consumer;
#[cfg(feature = "changes-producer")]
pub mod producer;

pub(crate) type Result<T> = std::result::Result<T, Error>;
