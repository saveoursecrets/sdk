//! Audit provider backend functions.
use crate::{Error, Result};
use sos_audit::{AuditEvent, AuditSink};
use sos_database::async_sqlite::Client;
use std::{path::Path, sync::OnceLock};

type AuditProviders =
    Vec<Box<dyn AuditSink<Error = Error> + Send + Sync + 'static>>;

static PROVIDERS: OnceLock<AuditProviders> = OnceLock::new();

/// Initialize audit trail providers.
pub fn init_audit_providers(providers: AuditProviders) {
    PROVIDERS.get_or_init(|| providers);
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

/// Create a database audit trail provider.
pub fn new_db_audit_provider(
    client: Client,
) -> impl AuditSink<Error = Error> {
    use sos_database::audit_provider::AuditDatabaseProvider;
    AuditDatabaseProvider::<Error>::new(client)
}

/// Create a file system audit trail provider.
pub fn new_fs_audit_provider(
    path: impl AsRef<Path>,
) -> impl AuditSink<Error = Error> {
    use sos_filesystem::audit_provider::AuditFileProvider;
    AuditFileProvider::<Error>::new(path.as_ref())
}
