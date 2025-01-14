use crate::Result;
use async_sqlite::rusqlite::{Connection, Error as SqlError, Row};
use sos_core::Origin;
use std::ops::Deref;
use url::Url;

/// Server row from the database.
#[doc(hidden)]
#[derive(Debug)]
pub struct ServerRow {
    pub row_id: i64,
    pub created_at: String,
    pub modified_at: String,
    pub name: String,
    pub url: String,
}

impl<'a> TryFrom<&Row<'a>> for ServerRow {
    type Error = SqlError;
    fn try_from(row: &Row<'a>) -> std::result::Result<Self, Self::Error> {
        Ok(ServerRow {
            row_id: row.get(0)?,
            created_at: row.get(1)?,
            modified_at: row.get(2)?,
            name: row.get(3)?,
            url: row.get(4)?,
        })
    }
}

impl TryFrom<ServerRow> for Origin {
    type Error = crate::Error;
    fn try_from(row: ServerRow) -> std::result::Result<Self, Self::Error> {
        Ok(Origin::new(row.name, row.url.parse()?))
    }
}

/// Server entity.
pub struct ServerEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    conn: &'conn C,
}

impl<'conn, C> ServerEntity<'conn, C>
where
    C: Deref<Target = Connection>,
{
    /// Create a new server entity.
    pub fn new(conn: &'conn C) -> Self {
        Self { conn }
    }

    /// Find a server in the database.
    pub fn find_one(
        &self,
        account_id: i64,
        url: &Url,
    ) -> std::result::Result<ServerRow, SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
                SELECT
                    server_id,
                    created_at,
                    modified_at,
                    name,
                    url
                FROM servers
                WHERE account_id=?1 AND url=?2
            "#,
        )?;
        Ok(stmt.query_row((account_id, url.to_string()), |row| {
            Ok(row.try_into()?)
        })?)
    }

    /// Load servers for an account.
    pub fn load_servers(&self, account_id: i64) -> Result<Vec<ServerRow>> {
        let mut stmt = self.conn.prepare_cached(
            r#"
                SELECT
                    server_id,
                    created_at,
                    modified_at,
                    name,
                    url
                FROM servers
                WHERE account_id=?1
            "#,
        )?;

        fn convert_row(row: &Row<'_>) -> Result<ServerRow> {
            Ok(row.try_into()?)
        }

        let rows = stmt.query_and_then([account_id], |row| {
            Ok::<_, crate::Error>(convert_row(row)?)
        })?;
        let mut servers = Vec::new();
        for row in rows {
            servers.push(row?);
        }
        Ok(servers)
    }

    /// Delete server origin from the database.
    pub fn delete_server(
        &self,
        server_id: i64,
    ) -> std::result::Result<(), SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
                DELETE FROM servers WHERE server_id=?1
            "#,
        )?;
        stmt.execute([server_id])?;
        Ok(())
    }

    /// Create server origin in the database.
    pub fn insert_server(
        &self,
        account_id: i64,
        server: Origin,
    ) -> std::result::Result<(), SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
              INSERT INTO servers
                (account_id, name, url)
                VALUES (?1, ?2, ?3)
            "#,
        )?;
        stmt.execute((account_id, server.name(), server.url().to_string()))?;
        Ok(())
    }

    /// Create server origins in the database.
    pub fn insert_servers(
        &self,
        account_id: i64,
        servers: Vec<Origin>,
    ) -> std::result::Result<(), SqlError> {
        for server in servers {
            self.insert_server(account_id, server)?;
        }
        Ok(())
    }
}
