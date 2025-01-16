#![deny(missing_docs)]
#![forbid(unsafe_code)]
//! Core types and traits for audit trail logging.
mod encoding;
mod event;

pub use event::*;

/// Trait for types that append to an audit log.
#[async_trait::async_trait]
pub trait AuditSink {
    /// Error type for this implementation.
    type Error: std::error::Error + std::fmt::Debug;

    /// Append audit log records to a destination.
    async fn append_audit_events(
        &self,
        events: &[AuditEvent],
    ) -> std::result::Result<(), Self::Error>;
}
