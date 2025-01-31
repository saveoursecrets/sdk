use super::prepare_server_for_upgrade;
use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_database::importer::{upgrade_accounts, UpgradeOptions};

/// Upgrade v1 accounts to the v2 backend for server-side storage.
#[tokio::test]
async fn database_upgrade_server() -> Result<()> {
    const TEST_ID: &str = "database_upgrade_server";
    // crate::test_utils::init_tracing();

    let dirs = setup(TEST_ID, 0).await?;
    prepare_server_for_upgrade(&dirs)?;

    let data_dir = dirs.test_dir;
    let backup_dir = data_dir.join("backups");

    // Upgrade the file system accounts into the db
    let options = UpgradeOptions {
        server: true,
        dry_run: false,
        backup_directory: Some(backup_dir),
        ..Default::default()
    };
    let result = upgrade_accounts(data_dir, options).await?;
    assert!(result.database_file.exists());

    assert!(result.backups.len() > 0);
    for file in &result.backups {
        assert!(file.exists());
    }

    teardown(TEST_ID).await;

    Ok(())
}
