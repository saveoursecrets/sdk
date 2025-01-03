use async_sqlite::rusqlite::{Connection, Error as SqlError};
use sos_sdk::audit::AuditEvent;
use std::ops::Deref;

type AuditSourceRow = (String, AuditEvent, Option<String>);

pub struct AuditEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    conn: &'conn C,
}

impl<'conn, C> AuditEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    /// Create a new audit entity.
    pub fn new(conn: &'conn C) -> Self {
        Self { conn }
    }

    /// Create audit logs in the database.
    pub fn insert_audit_logs(
        &self,
        events: Vec<AuditSourceRow>,
    ) -> std::result::Result<(), SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
              INSERT INTO audit_logs
                (created_at, account_identifier, event_kind, event_data)
                VALUES (?1, ?2, ?3, ?4)
            "#,
        )?;
        for (time, event, data) in events {
            stmt.execute((
                time,
                event.account_id().to_string(),
                event.event_kind().to_string(),
                data,
            ))?;
        }
        Ok(())
    }
}
