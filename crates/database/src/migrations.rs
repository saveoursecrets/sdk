use crate::Result;
use async_sqlite::{ClientBuilder, JournalMode};
use refinery::Report;
use std::path::Path;
use tokio::sync::oneshot;

mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("sql_migrations");
}

/// Run migrations on a file-based database.
pub async fn migrate_db_file(path: impl AsRef<Path>) -> Result<Report> {
    let client = ClientBuilder::new()
        .path(path)
        .journal_mode(JournalMode::Wal)
        .open()
        .await?;

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

/// Run migrations on an in-memory database.
pub async fn migrate_db_memory() -> Result<Report> {
    let client = ClientBuilder::new().open().await?;

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

#[cfg(test)]
mod test {
    use super::{migrate_db_file, migrate_db_memory};
    use anyhow::Result;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn migrations_file() -> Result<()> {
        let temp = NamedTempFile::new()?;
        let report = migrate_db_file(temp.path()).await?;
        println!("{:#?}", report);
        Ok(())
    }

    #[tokio::test]
    async fn migrations_memory() -> Result<()> {
        let report = migrate_db_memory().await?;
        println!("{:#?}", report);
        Ok(())
    }
}
