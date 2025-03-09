use anyhow::Result;
use async_sqlite::ClientBuilder;
use sos_database::{migrations::migrate_client, open_file};
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
