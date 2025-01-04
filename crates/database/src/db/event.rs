use async_sqlite::rusqlite::{
    CachedStatement, Connection, Error as SqlError,
};
use sos_core::commit::CommitHash;
use sos_sdk::events::EventRecord;
use std::ops::Deref;

type EventSourceRow = (String, CommitHash, EventRecord);

/// Event entity.
pub struct EventEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    conn: &'conn C,
}

impl<'conn, C> EventEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    /// Create a new event entity.
    pub fn new(conn: &'conn C) -> Self {
        Self { conn }
    }

    /// Create folder events in the database.
    pub fn insert_folder_events(
        &self,
        folder_id: i64,
        events: Vec<EventSourceRow>,
    ) -> Result<(), SqlError> {
        let stmt = self.conn.prepare_cached(
            r#"
              INSERT INTO folder_events
              (folder_id, created_at, commit_hash, event)
              VALUES (?1, ?2, ?3, ?4)"#,
        )?;
        create_events(stmt, folder_id, events)
    }

    /// Create account events in the database.
    pub fn insert_account_events(
        &self,
        account_id: i64,
        events: Vec<EventSourceRow>,
    ) -> std::result::Result<(), SqlError> {
        let stmt = self.conn.prepare_cached(
            r#"
          INSERT INTO account_events
            (account_id, created_at, commit_hash, event)
            VALUES (?1, ?2, ?3, ?4)
        "#,
        )?;
        create_events(stmt, account_id, events)
    }

    /// Create device events in the database.
    pub fn insert_device_events(
        &self,
        account_id: i64,
        events: Vec<(String, CommitHash, EventRecord)>,
    ) -> std::result::Result<(), SqlError> {
        let stmt = self.conn.prepare_cached(
            r#"
              INSERT INTO device_events
                (account_id, created_at, commit_hash, event)
                VALUES (?1, ?2, ?3, ?4)
            "#,
        )?;
        create_events(stmt, account_id, events)
    }

    /// Create file events in the database.
    pub fn insert_file_events(
        &self,
        account_id: i64,
        events: Vec<EventSourceRow>,
    ) -> std::result::Result<(), SqlError> {
        let stmt = self.conn.prepare_cached(
            r#"
              INSERT INTO file_events
                (account_id, created_at, commit_hash, event)
                VALUES (?1, ?2, ?3, ?4)
            "#,
        )?;
        create_events(stmt, account_id, events)
    }
}

fn create_events(
    mut stmt: CachedStatement<'_>,
    id: i64,
    events: Vec<EventSourceRow>,
) -> std::result::Result<(), SqlError> {
    for (time, commit, record) in events {
        stmt.execute((&id, time, commit.as_ref(), record.event_bytes()))?;
    }
    Ok(())
}
