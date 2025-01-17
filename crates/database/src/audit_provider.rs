//! Database audit log provider.
use crate::{db::AuditEntity, Error};
use async_sqlite::Client;
use async_trait::async_trait;
use sos_audit::{AuditEvent, AuditSink};

/// Audit provider that appends to a database table.
pub struct AuditDatabaseProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<crate::Error>
        + Send
        + Sync
        + 'static,
{
    client: Client,
    marker: std::marker::PhantomData<E>,
}

impl<E> AuditDatabaseProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<crate::Error>
        + Send
        + Sync
        + 'static,
{
    /// Create a new audit file provider.
    pub fn new(client: Client) -> Self {
        Self {
            client,
            marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<E> AuditSink for AuditDatabaseProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<crate::Error>
        + Send
        + Sync
        + 'static,
{
    type Error = E;

    async fn append_audit_events(
        &self,
        events: &[AuditEvent],
    ) -> std::result::Result<(), Self::Error> {
        let mut audit_events = Vec::new();
        for event in events {
            audit_events.push(event.try_into()?);
        }
        self.client
            .conn(move |conn| {
                let audit = AuditEntity::new(&conn);
                audit.insert_audit_logs(audit_events)?;
                Ok(())
            })
            .await
            .map_err(Error::from)?;
        Ok(())
    }
}
