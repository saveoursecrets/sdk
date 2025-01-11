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

type EventSourceRow = (String, EventRecord);

/// Commit row.
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
pub struct EventRecordRow {
    /// Row identifier.
    pub row_id: i64,
    /// Row created date and time.
    pub created_at: String,
    /// Commit hash.
    pub commit_hash: Vec<u8>,
    /// Event bytes.
    pub event_bytes: Vec<u8>,
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
            UtcDateTime::parse_utc_iso8601(&value.created_at)?,
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

    /// Insert events into an event log table.
    pub fn insert_events(
        &self,
        table: EventTable,
        account_id: i64,
        events: Vec<EventSourceRow>,
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
        self.create_events(stmt, account_id, events)
    }

    /// Create account events in the database.
    pub fn insert_account_events(
        &self,
        account_id: i64,
        events: Vec<EventSourceRow>,
    ) -> Result<Vec<i64>, SqlError> {
        self.insert_events(EventTable::AccountEvents, account_id, events)
    }

    /// Create folder events in the database.
    pub fn insert_folder_events(
        &self,
        folder_id: i64,
        events: Vec<EventSourceRow>,
    ) -> Result<Vec<i64>, SqlError> {
        self.insert_events(EventTable::FolderEvents, folder_id, events)
    }

    /// Create device events in the database.
    pub fn insert_device_events(
        &self,
        account_id: i64,
        events: Vec<EventSourceRow>,
    ) -> Result<Vec<i64>, SqlError> {
        self.insert_events(EventTable::DeviceEvents, account_id, events)
    }

    /// Create file events in the database.
    pub fn insert_file_events(
        &self,
        account_id: i64,
        events: Vec<EventSourceRow>,
    ) -> Result<Vec<i64>, SqlError> {
        self.insert_events(EventTable::FileEvents, account_id, events)
    }

    /// Load commits and identifiers for a folder.
    pub fn load_commits(
        &self,
        table: EventTable,
        account_id: i64,
        folder_id: Option<i64>,
    ) -> Result<Vec<CommitRow>, SqlError> {
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

        let rows =
            stmt.query_map([id], |row| Ok((row.get(0), row.get(1))))?;

        let mut commits = Vec::new();
        for row in rows {
            let res = row?;
            let commit = CommitRow {
                row_id: res.0?,
                commit_hash: res.1?,
            };
            commits.push(commit);
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
        events: Vec<EventSourceRow>,
    ) -> Result<Vec<i64>, SqlError> {
        let mut ids = Vec::new();
        for (time, record) in events {
            stmt.execute((
                &id,
                time,
                record.commit().as_ref(),
                record.event_bytes(),
            ))?;
            ids.push(self.conn.last_insert_rowid());
        }
        Ok(ids)
    }
}
