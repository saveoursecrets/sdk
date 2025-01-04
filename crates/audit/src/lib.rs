#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Audit trail logging.
mod encoding;
mod error;
mod event;
pub mod fs;

pub use error::Error;
pub use event::*;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Trait for types that append to an audit log.
#[async_trait::async_trait]
pub trait AuditSink {
    /// Error type for this implementation.
    type Error;

    /// Append audit log records to a destination.
    async fn append_audit_events(
        &self,
        events: &[AuditEvent],
    ) -> std::result::Result<(), Self::Error>;
}

use sos_core::Paths;
use std::sync::OnceLock;

type AuditProviders =
    Vec<Box<dyn AuditSink<Error = Error> + Send + Sync + 'static>>;

static PROVIDERS: OnceLock<AuditProviders> = OnceLock::new();

/// Initialize audit trail providers.
pub fn init_audit_providers(providers: AuditProviders) {
    PROVIDERS.get_or_init(|| providers);
}

/// Use default audit trail providers.
pub async fn default_audit_providers(paths: &Paths) {
    let log_file = fs::AuditFileProvider::new(paths.audit_file());
    init_audit_providers(vec![Box::new(log_file)]);
}

/// Append audit events to all configured providers.
pub async fn append_audit_events(events: Vec<AuditEvent>) -> Result<()> {
    let providers = PROVIDERS
        .get()
        .ok_or_else(|| Error::AuditProvidersNotConfigured)?;
    for provider in providers {
        provider.append_audit_events(events.as_slice()).await?;
    }
    Ok(())
}
