use super::prepare_client_for_upgrade;
use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_database::importer::{upgrade_accounts, UpgradeOptions};

/// Upgrade v1 accounts to the v2 backend for client-side storage.
#[tokio::test]
async fn database_upgrade_client() -> Result<()> {
    const TEST_ID: &str = "database_upgrade_client";
    // crate::test_utils::init_tracing();

    let dirs = setup(TEST_ID, 0).await?;
    prepare_client_for_upgrade(&dirs)?;

    // Upgrade the file system accounts into the db
    let options = UpgradeOptions {
        dry_run: false,
        ..Default::default()
    };
    let result = upgrade_accounts(dirs.test_dir.clone(), options).await?;
    assert!(result.database_file.exists());

    teardown(TEST_ID).await;

    Ok(())
}
