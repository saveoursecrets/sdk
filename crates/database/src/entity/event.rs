use crate::Error;
use async_sqlite::rusqlite::{
    CachedStatement, Connection, Error as SqlError, Row,
};
use sos_core::{
    commit::CommitHash,
    events::{EventLogType, EventRecord},
    UtcDateTime,
};
use sql_query_builder as sql;
use std::ops::Deref;

fn event_select_columns(sql: sql::Select) -> sql::Select {
    sql.select(
        r#"
            event_id, created_at, commit_hash, event
        "#,
    )
}

/// Enumeration of tables for events.
#[derive(Debug, Copy, Clone)]
enum EventTable {
    /// Account events table.
    AccountEvents,
    /// Folder events table.
    FolderEvents,
    /// Device events table.
    DeviceEvents,
    /// File events table.
    FileEvents,
}

impl From<EventLogType> for EventTable {
    fn from(value: EventLogType) -> Self {
        match value {
            EventLogType::Account => Self::AccountEvents,
            EventLogType::Identity => Self::FolderEvents,
            EventLogType::Device => Self::DeviceEvents,
            EventLogType::Files => Self::FileEvents,
            EventLogType::Folder(_) => Self::FolderEvents,
        }
    }
}

impl EventTable {
    /// Table name.
    pub fn as_str(&self) -> &'static str {
        match self {
            EventTable::AccountEvents => "account_events",
            EventTable::FolderEvents => "folder_events",
            EventTable::DeviceEvents => "device_events",
            EventTable::FileEvents => "file_events",
        }
    }

    /// Identifier column name.
    ///
    /// Events for a folder belong to a folder, other event logs
    /// belong to the account.
    pub fn id_column(&self) -> &'static str {
        match self {
            EventTable::FolderEvents => "folder_id",
            _ => "account_id",
        }
    }
}

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

impl<'conn> EventEntity<'conn, Box<Connection>> {
    /// Query to find all events.
    pub fn find_all_query(
        log_type: EventLogType,
        reverse: bool,
    ) -> sql::Select {
        let table: EventTable = log_type.into();
        let mut query = event_select_columns(sql::Select::new())
            .from(table.as_str())
            .where_clause(&format!("{}=?1", table.id_column()));
        if reverse {
            query = query.order_by("event_id DESC");
        } else {
            query = query.order_by("event_id ASC");
        }
        query
    }
}

impl<'conn, C> EventEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    /// Create a new event entity.
    pub fn new(conn: &'conn C) -> Self {
        Self { conn }
    }

    /// Find an event record in the database.
    pub fn find_one(
        &self,
        log_type: EventLogType,
        event_id: i64,
    ) -> Result<EventRecordRow, SqlError> {
        let table: EventTable = log_type.into();
        let query = event_select_columns(sql::Select::new())
            .from(table.as_str())
            .where_clause("event_id=?1");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        Ok(stmt.query_row([event_id], |row| Ok(row.try_into()?))?)
    }

    /// Delete an event from the database table.
    pub fn delete_one(
        &self,
        log_type: EventLogType,
        commit_hash: &CommitHash,
    ) -> Result<(), SqlError> {
        let table: EventTable = log_type.into();
        let query = sql::Delete::new()
            .delete_from(table.as_str())
            .where_clause("commit_hash = ?1");
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        stmt.execute([commit_hash.as_ref()])?;
        Ok(())
    }

    /// Insert events into an event log table.
    pub fn insert_events(
        &self,
        log_type: EventLogType,
        account_or_folder_id: i64,
        events: &[EventRecordRow],
    ) -> Result<Vec<i64>, SqlError> {
        let table: EventTable = log_type.into();
        let query = sql::Insert::new()
            .insert_into(&format!(
                "{} ({}, created_at, commit_hash, event)",
                table.as_str(),
                table.id_column()
            ))
            .values("(?1, ?2, ?3, ?4)");
        let stmt = self.conn.prepare_cached(&query.as_string())?;
        self.create_events(stmt, account_or_folder_id, events)
    }

    /// Create account events in the database.
    pub fn insert_account_events(
        &self,
        account_id: i64,
        events: &[EventRecordRow],
    ) -> Result<Vec<i64>, SqlError> {
        self.insert_events(EventLogType::Account, account_id, events)
    }

    /// Create folder events in the database.
    pub fn insert_folder_events(
        &self,
        folder_id: i64,
        events: &[EventRecordRow],
    ) -> Result<Vec<i64>, SqlError> {
        self.insert_events(EventLogType::Identity, folder_id, events)
    }

    /// Create device events in the database.
    pub fn insert_device_events(
        &self,
        account_id: i64,
        events: &[EventRecordRow],
    ) -> Result<Vec<i64>, SqlError> {
        self.insert_events(EventLogType::Device, account_id, events)
    }

    /// Create file events in the database.
    pub fn insert_file_events(
        &self,
        account_id: i64,
        events: &[EventRecordRow],
    ) -> Result<Vec<i64>, SqlError> {
        self.insert_events(EventLogType::Files, account_id, events)
    }

    /// Load event records for a folder.
    pub fn load_events(
        &self,
        log_type: EventLogType,
        account_id: i64,
        folder_id: Option<i64>,
    ) -> crate::Result<Vec<EventRecordRow>> {
        let id = folder_id.unwrap_or(account_id);
        let table: EventTable = log_type.into();
        let query = event_select_columns(sql::Select::new())
            .from(table.as_str())
            .where_clause(&format!("{}=?1", table.id_column()))
            .order_by("event_id ASC");

        let mut stmt = self.conn.prepare_cached(&query.as_string())?;

        fn convert_row(
            row: &Row<'_>,
        ) -> Result<EventRecordRow, crate::Error> {
            Ok(row.try_into()?)
        }

        let rows = stmt.query_and_then([id], |row| {
            Ok::<_, crate::Error>(convert_row(row)?)
        })?;

        let mut events = Vec::new();
        for row in rows {
            events.push(row?);
        }
        Ok(events)
    }

    /// Load commits and identifiers for a folder.
    pub fn load_commits(
        &self,
        log_type: EventLogType,
        account_or_folder_id: i64,
    ) -> crate::Result<Vec<CommitRow>> {
        let table: EventTable = log_type.into();
        let query = sql::Select::new()
            .select("event_id, commit_hash")
            .from(table.as_str())
            .where_clause(&format!("{}=?1", table.id_column()))
            .order_by("event_id ASC");

        let mut stmt = self.conn.prepare_cached(&query.as_string())?;

        fn convert_row(row: &Row<'_>) -> Result<CommitRow, crate::Error> {
            Ok(row.try_into()?)
        }

        let rows = stmt.query_and_then([account_or_folder_id], |row| {
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
        log_type: EventLogType,
        account_or_folder_id: i64,
    ) -> Result<usize, SqlError> {
        let table: EventTable = log_type.into();
        let query = sql::Delete::new()
            .delete_from(table.as_str())
            .where_clause(&format!("{}=?1", table.id_column()));
        let mut stmt = self.conn.prepare_cached(&query.as_string())?;
        Ok(stmt.execute([account_or_folder_id])?)
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
