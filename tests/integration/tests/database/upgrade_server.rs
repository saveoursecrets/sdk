use super::prepare_server_for_upgrade;
use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_core::Paths;
use sos_database_upgrader::{upgrade_accounts, UpgradeOptions};

/// Upgrade v1 accounts to the v2 backend for server-side storage.
#[tokio::test]
async fn database_upgrade_server() -> Result<()> {
    const TEST_ID: &str = "database_upgrade_server";
    // crate::test_utils::init_tracing();

    let dirs = setup(TEST_ID, 0).await?;
    prepare_server_for_upgrade(&dirs)?;

    let backup_dir = dirs.test_dir.join("backups");

    // Upgrade the file system accounts into the db
    let options = UpgradeOptions {
        paths: Paths::new_global_server(&dirs.test_dir),
        dry_run: false,
        backup_directory: Some(backup_dir),
        ..Default::default()
    };
    let result = upgrade_accounts(dirs.test_dir.clone(), options).await?;
    assert!(result.database_file.exists());

    assert!(result.backups.len() > 0);
    for file in &result.backups {
        assert!(file.exists());
    }

    teardown(TEST_ID).await;

    Ok(())
}
