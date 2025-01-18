use crate::Error;
use async_sqlite::rusqlite::{Connection, Error as SqlError, Row};
use sos_audit::AuditEvent;
use sos_core::{events::EventKind, AccountId, UtcDateTime};
use std::ops::Deref;

/// Audit row.
#[doc(hidden)]
#[derive(Default, Debug)]
pub struct AuditRow {
    /// Row identifier.
    pub row_id: i64,
    /// RFC3339 date and time.
    created_at: String,
    /// Account identifier.
    account_id: String,
    /// Event kind string.
    event_kind: String,
    /// Associated data encoded as JSON.
    data: Option<String>,
}

impl TryFrom<&AuditEvent> for AuditRow {
    type Error = Error;

    fn try_from(value: &AuditEvent) -> Result<Self, Self::Error> {
        let data = if let Some(data) = value.data() {
            Some(serde_json::to_string(data)?)
        } else {
            None
        };
        Ok(Self {
            created_at: value.time().to_rfc3339()?,
            account_id: value.account_id().to_string(),
            event_kind: value.event_kind().to_string(),
            data,
            ..Default::default()
        })
    }
}

impl<'a> TryFrom<&Row<'a>> for AuditRow {
    type Error = SqlError;
    fn try_from(row: &Row<'a>) -> Result<Self, Self::Error> {
        Ok(AuditRow {
            row_id: row.get(0)?,
            created_at: row.get(1)?,
            account_id: row.get(2)?,
            event_kind: row.get(3)?,
            data: row.get(4)?,
        })
    }
}

/// Audit record.
pub struct AuditRecord {
    /// Row identifier.
    pub row_id: i64,
    /// Audit event.
    pub event: AuditEvent,
}

impl TryFrom<AuditRow> for AuditRecord {
    type Error = Error;

    fn try_from(value: AuditRow) -> Result<Self, Self::Error> {
        let data = if let Some(data) = value.data {
            Some(serde_json::from_str(&data)?)
        } else {
            None
        };

        let date_time = UtcDateTime::parse_rfc3339(&value.created_at)?;
        let account_id: AccountId = value.account_id.parse()?;
        let event_kind: EventKind = value.event_kind.parse()?;
        let event = AuditEvent::new(date_time, event_kind, account_id, data);

        Ok(AuditRecord {
            row_id: value.row_id,
            event,
        })
    }
}

/// Audit entity.
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
    pub fn insert_audit_log(
        &self,
        event: &AuditRow,
    ) -> std::result::Result<(), SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
              INSERT INTO audit_logs
                (created_at, account_identifier, event_kind, event_data)
                VALUES (?1, ?2, ?3, ?4)
            "#,
        )?;
        stmt.execute((
            &event.created_at,
            &event.account_id,
            &event.event_kind,
            &event.data,
        ))?;

        Ok(())
    }

    /// Create audit logs in the database.
    pub fn insert_audit_logs(
        &self,
        events: &[AuditRow],
    ) -> std::result::Result<(), SqlError> {
        for event in events {
            self.insert_audit_log(event)?;
        }
        Ok(())
    }
}
