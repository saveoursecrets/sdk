use async_sqlite::rusqlite::{Connection, Error as SqlError};
use sos_core::Origin;
use std::ops::Deref;

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

    /// Create server origins in the database.
    pub fn insert_servers(
        &self,
        account_id: i64,
        servers: Vec<Origin>,
    ) -> Result<(), SqlError> {
        let mut stmt = self.conn.prepare_cached(
            r#"
              INSERT INTO servers
                (account_id, name, url)
                VALUES (?1, ?2, ?3)
            "#,
        )?;

        for server in servers {
            stmt.execute((
                account_id,
                server.name(),
                server.url().to_string(),
            ))?;
        }

        Ok(())
    }
}
