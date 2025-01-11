use crate::{db::FolderEntity, Error};
use async_sqlite::rusqlite::{
    CachedStatement, Connection, Error as SqlError, Row,
};
use sos_core::{commit::CommitHash, events::EventRecord, VaultId};
use std::ops::Deref;

type EventSourceRow = (String, CommitHash, EventRecord);

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
    ) -> Result<(), SqlError> {
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
    ) -> Result<(), SqlError> {
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
    ) -> Result<(), SqlError> {
        let stmt = self.conn.prepare_cached(
            r#"
              INSERT INTO file_events
                (account_id, created_at, commit_hash, event)
                VALUES (?1, ?2, ?3, ?4)
            "#,
        )?;
        create_events(stmt, account_id, events)
    }

    /// Load commits and identifiers for a folder.
    pub fn load_commits(
        &self,
        folder_id: &VaultId,
    ) -> Result<Vec<CommitRow>, SqlError> {
        let folder = FolderEntity::new(self.conn);
        let row = folder.find_one(folder_id)?;
        let mut stmt = self.conn.prepare_cached(
            r#"
                SELECT
                    event_id,
                    commit_hash
                    FROM folder_events
                    WHERE folder_id=?1
                    ORDER BY event_id ASC
            "#,
        )?;
        let rows =
            stmt.query_map([row.row_id], |row| Ok((row.get(0), row.get(1))))?;

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

    /// Delete all folder events.
    pub fn delete_all_events(
        &self,
        folder_id: &VaultId,
    ) -> Result<usize, SqlError> {
        let folder = FolderEntity::new(self.conn);
        let row = folder.find_one(folder_id)?;
        let mut stmt = self.conn.prepare_cached(
            r#"
                DELETE
                    FROM folder_events
                    WHERE folder_id=?1
            "#,
        )?;
        Ok(stmt.execute([row.row_id])?)
    }
}

fn create_events(
    mut stmt: CachedStatement<'_>,
    id: i64,
    events: Vec<EventSourceRow>,
) -> Result<(), SqlError> {
    for (time, commit, record) in events {
        stmt.execute((&id, time, commit.as_ref(), record.event_bytes()))?;
    }
    Ok(())
}
