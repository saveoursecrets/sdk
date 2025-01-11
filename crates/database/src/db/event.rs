use crate::{db::FolderEntity, Error};
use async_sqlite::rusqlite::{
    CachedStatement, Connection, Error as SqlError, Row,
};
use sos_core::{commit::CommitHash, events::EventRecord, VaultId};
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

    /// Insert events into an event log table.
    pub fn insert_events(
        &self,
        table: EventTable,
        account_id: i64,
        events: Vec<EventSourceRow>,
    ) -> Result<(), SqlError> {
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
        create_events(stmt, account_id, events)
    }

    /// Create account events in the database.
    pub fn insert_account_events(
        &self,
        account_id: i64,
        events: Vec<EventSourceRow>,
    ) -> Result<(), SqlError> {
        self.insert_events(EventTable::AccountEvents, account_id, events)
    }

    /// Create folder events in the database.
    pub fn insert_folder_events(
        &self,
        folder_id: i64,
        events: Vec<EventSourceRow>,
    ) -> Result<(), SqlError> {
        self.insert_events(EventTable::FolderEvents, folder_id, events)
    }

    /// Create device events in the database.
    pub fn insert_device_events(
        &self,
        account_id: i64,
        events: Vec<EventSourceRow>,
    ) -> Result<(), SqlError> {
        self.insert_events(EventTable::DeviceEvents, account_id, events)
    }

    /// Create file events in the database.
    pub fn insert_file_events(
        &self,
        account_id: i64,
        events: Vec<EventSourceRow>,
    ) -> Result<(), SqlError> {
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
}

fn create_events(
    mut stmt: CachedStatement<'_>,
    id: i64,
    events: Vec<EventSourceRow>,
) -> Result<(), SqlError> {
    for (time, record) in events {
        stmt.execute((
            &id,
            time,
            record.commit().as_ref(),
            record.event_bytes(),
        ))?;
    }
    Ok(())
}
