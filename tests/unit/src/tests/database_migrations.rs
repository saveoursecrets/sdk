use anyhow::Result;
use async_sqlite::ClientBuilder;
use sos_database::{db::open_file, migrations::migrate_client};
use tempfile::NamedTempFile;

#[tokio::test]
async fn migrations_file() -> Result<()> {
    let temp = NamedTempFile::new()?;
    let mut client = open_file(temp.path()).await?;
    let report = migrate_client(&mut client).await;
    // println!("{:#?}", report);
    assert!(report.is_ok());
    Ok(())
}

#[tokio::test]
async fn migrations_memory() -> Result<()> {
    let mut client = ClientBuilder::new().open().await?;
    let report = migrate_client(&mut client).await;
    // println!("{:#?}", report);
    assert!(report.is_ok());
    Ok(())
}
