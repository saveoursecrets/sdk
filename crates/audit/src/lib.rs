//! Core types and traits for audit trail logging.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

mod encoding;
mod event;

pub use event::*;

use futures::stream::BoxStream;

/// Trait for types that read and write audit logs.
#[async_trait::async_trait]
pub trait AuditStreamSink {
    /// Error type for this implementation.
    type Error: std::error::Error + std::fmt::Debug;

    /// Append audit log records to a destination.
    async fn append_audit_events(
        &self,
        events: &[AuditEvent],
    ) -> std::result::Result<(), Self::Error>;

    /// Stream of audit log records.
    async fn audit_stream(
        &self,
        reverse: bool,
    ) -> Result<
        BoxStream<'static, Result<AuditEvent, Self::Error>>,
        Self::Error,
    >;
}
