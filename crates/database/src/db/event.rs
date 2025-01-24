use crate::Error;
use async_sqlite::rusqlite::{
    CachedStatement, Connection, Error as SqlError, Row,
};
use sos_core::{commit::CommitHash, events::EventRecord, UtcDateTime};
use std::ops::Deref;

/// Enumeration of tables for events.
#[derive(Debug, Copy, Clone)]
pub enum EventTable {
    /// Account events table.
    AccountEvents,
    /// Folder events table.
    FolderEvents,
    /// Device events table.
    DeviceEvents,
    /// File events table.
    FileEvents,
}

// type EventSourceRow = (String, EventRecord);

/// Commit row.
#[derive(Debug)]
pub struct CommitRow {
    /// Row identifier.
    pub row_id: i64,
    /// Commit hash.
    pub commit_hash: Vec<u8>,
}

impl<'a> TryFrom<&Row<'a>> for CommitRow {
    type Error = SqlError;
    fn try_from(row: &Row<'a>) -> Result<Self, Self::Error> {
        Ok(CommitRow {
            row_id: row.get(0)?,
            commit_hash: row.get(1)?,
        })
    }
}

/// Commit record.
pub struct CommitRecord {
    /// Row identifier.
    pub row_id: i64,
    /// Commit hash.
    pub commit_hash: CommitHash,
}

impl TryFrom<CommitRow> for CommitRecord {
    type Error = Error;

    fn try_from(value: CommitRow) -> Result<Self, Self::Error> {
        Ok(CommitRecord {
            row_id: value.row_id,
            commit_hash: CommitHash(value.commit_hash.as_slice().try_into()?),
        })
    }
}

/// Commit record row.
#[derive(Debug, Default)]
pub struct EventRecordRow {
    /// Row identifier.
    pub row_id: i64,
    /// Row created date and time.
    created_at: String,
    /// Commit hash.
    commit_hash: Vec<u8>,
    /// Event bytes.
    event_bytes: Vec<u8>,
}

impl EventRecordRow {
    /// Create a new event record row for insertion.
    pub fn new(record: &EventRecord) -> Result<Self, Error> {
        Ok(Self {
            created_at: record.time().to_rfc3339()?,
            commit_hash: record.commit().as_ref().to_vec(),
            event_bytes: record.event_bytes().to_vec(),
            ..Default::default()
        })
    }
}

impl<'a> TryFrom<&Row<'a>> for EventRecordRow {
    type Error = SqlError;
    fn try_from(row: &Row<'a>) -> Result<Self, Self::Error> {
        Ok(EventRecordRow {
            row_id: row.get(0)?,
            created_at: row.get(1)?,
            commit_hash: row.get(2)?,
            event_bytes: row.get(3)?,
        })
    }
}

impl TryFrom<EventRecordRow> for EventRecord {
    type Error = Error;

    fn try_from(value: EventRecordRow) -> Result<Self, Self::Error> {
        Ok(EventRecord::new(
            UtcDateTime::parse_rfc3339(&value.created_at)?,
            Default::default(),
            CommitHash(value.commit_hash.as_slice().try_into()?),
            value.event_bytes,
        ))
    }
}

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

    /// Find a event record in the database.
    pub fn find_one(
        &self,
        table: EventTable,
        event_id: i64,
    ) -> Result<EventRecordRow, SqlError> {
        let mut stmt = match table {
            EventTable::AccountEvents => self.conn.prepare_cached(
                r#"
                    SELECT
                        event_id,
                        created_at,
                        commit_hash,
                        event
                    FROM account_events
                    WHERE event_id=?1
                "#,
            )?,
            EventTable::FolderEvents => self.conn.prepare_cached(
                r#"
                    SELECT
                        event_id,
                        created_at,
                        commit_hash,
                        event
                    FROM folder_events
                    WHERE event_id=?1
                "#,
            )?,
            EventTable::DeviceEvents => self.conn.prepare_cached(
                r#"
                    SELECT
                        event_id,
                        created_at,
                        commit_hash,
                        event
                    FROM device_events
                    WHERE event_id=?1
                "#,
            )?,
            EventTable::FileEvents => self.conn.prepare_cached(
                r#"
                    SELECT
                        event_id,
                        created_at,
                        commit_hash,
                        event
                    FROM file_events
                    WHERE event_id=?1
                "#,
            )?,
        };

        Ok(stmt.query_row([event_id], |row| Ok(row.try_into()?))?)
    }

    /// Delete an event from the database table.
    pub fn delete_one(
        &self,
        table: EventTable,
        event_id: i64,
    ) -> Result<(), SqlError> {
        let mut stmt = match table {
            EventTable::AccountEvents => self.conn.prepare_cached(
                r#"
                    DELETE
                    FROM account_events
                    WHERE event_id=?1
                    "#,
            )?,
            EventTable::FolderEvents => self.conn.prepare_cached(
                r#"
                    DELETE
                    FROM folder_events
                    WHERE event_id=?1
                    "#,
            )?,
            EventTable::DeviceEvents => self.conn.prepare_cached(
                r#"
                    DELETE
                    FROM device_events
                    WHERE event_id=?1
                    "#,
            )?,
            EventTable::FileEvents => self.conn.prepare_cached(
                r#"
                    DELETE
                    FROM file_events
                    WHERE event_id=?1
                    "#,
            )?,
        };
        stmt.execute([event_id])?;
        Ok(())
    }

    /// Insert events into an event log table.
    pub fn insert_events(
        &self,
        table: EventTable,
        account_or_folder_id: i64,
        events: &[EventRecordRow],
    ) -> Result<Vec<i64>, SqlError> {
        let stmt = match table {
            EventTable::AccountEvents => {
                self.conn.prepare_cached(&format!(
                    r#"
                      INSERT INTO {}
                        (account_id, created_at, commit_hash, event)
                        VALUES (?1, ?2, ?3, ?4)
                    "#,
                    "account_events"
                ))?
            }
            EventTable::FolderEvents => {
                self.conn.prepare_cached(&format!(
                    r#"
                      INSERT INTO {}
                        (folder_id, created_at, commit_hash, event)
                        VALUES (?1, ?2, ?3, ?4)
                    "#,
                    "folder_events"
                ))?
            }
            EventTable::DeviceEvents => {
                self.conn.prepare_cached(&format!(
                    r#"
                      INSERT INTO {}
                        (account_id, created_at, commit_hash, event)
                        VALUES (?1, ?2, ?3, ?4)
                    "#,
                    "device_events"
                ))?
            }
            EventTable::FileEvents => self.conn.prepare_cached(&format!(
                r#"
                      INSERT INTO {}
                        (account_id, created_at, commit_hash, event)
                        VALUES (?1, ?2, ?3, ?4)
                    "#,
                "file_events"
            ))?,
        };
        self.create_events(stmt, account_or_folder_id, events)
    }

    /// Create account events in the database.
    pub fn insert_account_events(
        &self,
        account_id: i64,
        events: &[EventRecordRow],
    ) -> Result<Vec<i64>, SqlError> {
        self.insert_events(EventTable::AccountEvents, account_id, events)
    }

    /// Create folder events in the database.
    pub fn insert_folder_events(
        &self,
        folder_id: i64,
        events: &[EventRecordRow],
    ) -> Result<Vec<i64>, SqlError> {
        self.insert_events(EventTable::FolderEvents, folder_id, events)
    }

    /// Create device events in the database.
    pub fn insert_device_events(
        &self,
        account_id: i64,
        events: &[EventRecordRow],
    ) -> Result<Vec<i64>, SqlError> {
        self.insert_events(EventTable::DeviceEvents, account_id, events)
    }

    /// Create file events in the database.
    pub fn insert_file_events(
        &self,
        account_id: i64,
        events: &[EventRecordRow],
    ) -> Result<Vec<i64>, SqlError> {
        self.insert_events(EventTable::FileEvents, account_id, events)
    }

    /// Load commits and identifiers for a folder.
    pub fn load_commits(
        &self,
        table: EventTable,
        account_id: i64,
        folder_id: Option<i64>,
    ) -> crate::Result<Vec<CommitRow>> {
        let (mut stmt, id) = match (table, folder_id) {
            (EventTable::AccountEvents, None) => {
                let stmt = self.conn.prepare_cached(
                    r#"
                        SELECT
                            event_id,
                            commit_hash
                        FROM account_events
                        WHERE account_id=?1
                        ORDER BY event_id ASC
                    "#,
                )?;
                (stmt, account_id)
            }
            (EventTable::FolderEvents, Some(folder_id)) => {
                let stmt = self.conn.prepare_cached(
                    r#"
                        SELECT
                            event_id,
                            commit_hash
                        FROM folder_events
                        WHERE folder_id=?1
                        ORDER BY event_id ASC
                    "#,
                )?;
                (stmt, folder_id)
            }
            (EventTable::DeviceEvents, None) => {
                let stmt = self.conn.prepare_cached(
                    r#"
                        SELECT
                            event_id,
                            commit_hash
                        FROM device_events
                        WHERE account_id=?1
                        ORDER BY event_id ASC
                    "#,
                )?;
                (stmt, account_id)
            }
            (EventTable::FileEvents, None) => {
                let stmt = self.conn.prepare_cached(
                    r#"
                        SELECT
                            event_id,
                            commit_hash
                        FROM file_events
                        WHERE account_id=?1
                        ORDER BY event_id ASC
                    "#,
                )?;
                (stmt, account_id)
            }
            _ => unreachable!(),
        };

        fn convert_row(row: &Row<'_>) -> Result<CommitRow, crate::Error> {
            Ok(row.try_into()?)
        }

        let rows = stmt.query_and_then([id], |row| {
            Ok::<_, crate::Error>(convert_row(row)?)
        })?;

        let mut commits = Vec::new();
        for row in rows {
            commits.push(row?);
        }
        Ok(commits)
    }

    /// Delete all event logs.
    pub fn delete_all_events(
        &self,
        table: EventTable,
        account_id: i64,
        folder_id: Option<i64>,
    ) -> Result<usize, SqlError> {
        let (mut stmt, id) = match (table, folder_id) {
            (EventTable::AccountEvents, None) => {
                let stmt = self.conn.prepare_cached(
                    r#"
                        DELETE
                            FROM account_events
                            WHERE account_id=?1
                    "#,
                )?;
                (stmt, account_id)
            }
            (EventTable::FolderEvents, Some(folder_id)) => {
                let stmt = self.conn.prepare_cached(
                    r#"
                        DELETE
                            FROM folder_events
                            WHERE folder_id=?1
                    "#,
                )?;
                (stmt, folder_id)
            }
            (EventTable::DeviceEvents, None) => {
                let stmt = self.conn.prepare_cached(
                    r#"
                        DELETE
                            FROM device_events
                            WHERE account_id=?1
                    "#,
                )?;
                (stmt, account_id)
            }
            (EventTable::FileEvents, None) => {
                let stmt = self.conn.prepare_cached(
                    r#"
                        DELETE
                            FROM file_events
                            WHERE account_id=?1
                    "#,
                )?;
                (stmt, account_id)
            }
            _ => unreachable!(),
        };
        Ok(stmt.execute([id])?)
    }

    fn create_events(
        &self,
        mut stmt: CachedStatement<'_>,
        id: i64,
        events: &[EventRecordRow],
    ) -> Result<Vec<i64>, SqlError> {
        let mut ids = Vec::new();
        for record in events {
            stmt.execute((
                &id,
                &record.created_at,
                &record.commit_hash,
                &record.event_bytes,
            ))?;
            ids.push(self.conn.last_insert_rowid());
        }
        Ok(ids)
    }
}
