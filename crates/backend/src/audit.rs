//! Audit provider backend functions.
use crate::{Error, Result};
use sos_audit::{AuditEvent, AuditStreamSink};
use sos_database::async_sqlite::Client;
use std::{path::Path, sync::OnceLock};

/// Boxed audit trail stream sink.
pub type AuditProvider =
    Box<dyn AuditStreamSink<Error = Error> + Send + Sync + 'static>;

type AuditProviders = Vec<AuditProvider>;

static mut PROVIDERS: OnceLock<AuditProviders> = OnceLock::new();

/// Initialize audit trail providers.
pub fn init_providers(providers: AuditProviders) {
    unsafe {
        PROVIDERS.get_or_init(|| providers);
    }
}

/// Update audit trail providers.
///
/// # Panics
///
/// If the audit trail providers have not already been set.
pub fn update_providers(providers: AuditProviders) {
    unsafe {
        let audit_providers = PROVIDERS.get_mut().unwrap();
        *audit_providers = providers;
    }
}

/// Configured audit providers.
pub fn providers<'a>() -> Option<&'a AuditProviders> {
    unsafe { PROVIDERS.get() }
}

/// Append audit events to all configured providers.
pub async fn append_audit_events(events: &[AuditEvent]) -> Result<()> {
    #[cfg(not(debug_assertions))]
    {
        let providers =
            providers().ok_or_else(|| Error::AuditProvidersNotConfigured)?;
        for provider in providers {
            provider.append_audit_events(events).await?;
        }
    }

    // For test specs we don't require an audit trail
    #[cfg(debug_assertions)]
    {
        if let Some(providers) = providers() {
            for provider in providers {
                provider.append_audit_events(events).await?;
            }
        }
    }
    Ok(())
}

/// Create a database audit trail provider.
pub fn new_db_provider(client: Client) -> AuditProvider {
    use sos_database::audit_provider::AuditDatabaseProvider;
    Box::new(AuditDatabaseProvider::<Error>::new(client))
}

/// Create a file system audit trail provider.
pub fn new_fs_provider(path: impl AsRef<Path>) -> AuditProvider {
    use sos_filesystem::audit_provider::AuditFileProvider;
    Box::new(AuditFileProvider::<Error>::new(path.as_ref()))
}
