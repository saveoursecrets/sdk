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

/// Change event sent over a local socket.
pub struct LocalChangeEvent {
    /// Account identifier.
    pub account_id: AccountId,
    /// Detail about the event.
    pub detail: LocalChangeDetail,
}

/// Detail for the event.
pub enum LocalChangeDetail {
    /// Change to an event log.
    EventLog {
        /// Type of the event log.
        log_type: EventLogType,
        /// Span of commit hashes.
        commit_span: CommitSpan,
    },
}
