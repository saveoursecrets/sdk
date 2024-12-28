use crate::test_utils::setup;
use anyhow::Result;

#[tokio::test]
async fn database_importer() -> Result<()> {
    const TEST_ID: &str = "database_importer";

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    Ok(())
}
