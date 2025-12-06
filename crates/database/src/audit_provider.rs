//! Database audit log provider.
use crate::{
    Error,
    entity::{AuditEntity, AuditRecord, AuditRow},
};
use async_sqlite::Client;
use async_trait::async_trait;
use futures::stream::BoxStream;
use sos_audit::{AuditEvent, AuditStreamSink};
use tokio_stream::wrappers::ReceiverStream;

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
impl<E> AuditStreamSink for AuditDatabaseProvider<E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<crate::Error>
        + From<std::io::Error>
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
                audit.insert_audit_logs(audit_events.as_slice())?;
                Ok(())
            })
            .await
            .map_err(Error::from)?;
        Ok(())
    }

    async fn audit_stream(
        &self,
        reverse: bool,
    ) -> std::result::Result<
        BoxStream<'static, std::result::Result<AuditEvent, Self::Error>>,
        Self::Error,
    > {
        let (tx, rx) = tokio::sync::mpsc::channel::<
            std::result::Result<AuditEvent, Self::Error>,
        >(16);

        let client = self.client.clone();
        tokio::task::spawn(async move {
            client
                .conn_and_then(move |conn| {
                    let mut stmt = if reverse {
                        conn.prepare(
                            "SELECT * FROM audit_logs ORDER BY log_id DESC",
                        )?
                    } else {
                        conn.prepare(
                            "SELECT * FROM audit_logs ORDER BY log_id ASC",
                        )?
                    };
                    let mut rows = stmt.query([])?;

                    while let Some(row) = rows.next()? {
                        if tx.is_closed() {
                            break;
                        }
                        let row: AuditRow = row.try_into()?;
                        let record: AuditRecord = row.try_into()?;
                        let inner_tx = tx.clone();
                        let res = futures::executor::block_on(async move {
                            inner_tx.send(Ok(record.event)).await
                        });
                        if let Err(e) = res {
                            tracing::error!(error = %e);
                            break;
                        }
                    }

                    Ok::<_, Error>(())
                })
                .await?;
            Ok::<_, Self::Error>(())
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }
}
