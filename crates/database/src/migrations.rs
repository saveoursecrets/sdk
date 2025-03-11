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
    tracing::debug!("migration::started");
    let report = embedded::migrations::runner().run(conn)?;
    let applied = report.applied_migrations();
    for migration in applied {
        tracing::debug!(
            name = %migration.name(),
            version = %migration.version(),
            "migration::applied",
        );
    }
    tracing::debug!(
        applied_migrations = %applied.len(),
        "migration::finished");
    Ok(report)
}

/// Run migrations for a client.
pub async fn migrate_client(client: &mut Client) -> Result<Report> {
    let (tx, rx) =
        oneshot::channel::<std::result::Result<Report, refinery::Error>>();
    client
        .conn_mut(|conn| {
            let result = migrate_connection(conn);
            tx.send(result).unwrap();
            Ok(())
        })
        .await?;
    Ok(rx.await.unwrap()?)
}
