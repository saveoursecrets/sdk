//! Run database migrations.
use crate::Result;
use async_sqlite::{Client, ClientBuilder, JournalMode};
use refinery::Report;
use std::path::Path;
use tokio::sync::oneshot;

mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("sql_migrations");
}

/// Run migrations on a file-based database.
pub async fn migrate_db_file(path: impl AsRef<Path>) -> Result<Report> {
    let mut client = ClientBuilder::new()
        .path(path)
        .journal_mode(JournalMode::Wal)
        .open()
        .await?;
    migrate_client(&mut client).await
}

/// Run migrations on an in-memory database.
pub async fn migrate_db_memory() -> Result<Report> {
    let mut client = ClientBuilder::new().open().await?;
    migrate_client(&mut client).await
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

    let res = rx.await;
    let report = res.unwrap()?;
    Ok(report)
}
