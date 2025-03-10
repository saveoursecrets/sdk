//! Run database migrations.
use crate::Result;
use async_sqlite::{rusqlite::Connection, Client};
use refinery::Report;
use tokio::sync::oneshot;

mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("sql_migrations");
}

/// Run migrations for a connection.
pub fn migrate_connection(
    conn: &mut Connection,
) -> std::result::Result<Report, refinery::Error> {
    embedded::migrations::runner().run(conn)
}

/// Run migrations for a client.
pub async fn migrate_client(client: &mut Client) -> Result<Report> {
    let (tx, rx) =
        oneshot::channel::<std::result::Result<Report, refinery::Error>>();
    client
        .conn_mut(|conn| {
            let result = embedded::migrations::runner().run(conn);
            tx.send(result).unwrap();
            Ok(())
        })
        .await?;
    Ok(rx.await.unwrap()?)
}
