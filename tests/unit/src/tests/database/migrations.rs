use anyhow::Result;
use sos_database::migrations::{migrate_db_file, migrate_db_memory};
use tempfile::NamedTempFile;

#[tokio::test]
async fn migrations_file() -> Result<()> {
    let temp = NamedTempFile::new()?;
    let report = migrate_db_file(temp.path()).await;
    // println!("{:#?}", report);
    assert!(report.is_ok());
    Ok(())
}

#[tokio::test]
async fn migrations_memory() -> Result<()> {
    let report = migrate_db_memory().await;
    // println!("{:#?}", report);
    assert!(report.is_ok());
    Ok(())
}
