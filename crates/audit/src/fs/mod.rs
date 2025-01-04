//! Audit trail provider backed by an append-only file.
mod log_file;
mod stream;

pub use log_file::{AuditFileProvider, AuditLogFile};
pub use stream::audit_stream;
