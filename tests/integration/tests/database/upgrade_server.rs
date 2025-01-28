use crate::test_utils::{copy_dir, setup, teardown};
use anyhow::Result;
use sos_database::importer::{upgrade_accounts, UpgradeOptions};
use sos_sdk::prelude::{IDENTITY_DIR, REMOTE_DIR};
use std::path::PathBuf;

/// Upgrade v1 accounts to the v2 backend for server-side storage.
#[tokio::test]
async fn database_upgrade_server() -> Result<()> {
    const TEST_ID: &str = "database_upgrade_server";
    // crate::test_utils::init_tracing();

    let dirs = setup(TEST_ID, 0).await?;
    let data_dir = dirs.test_dir;

    let v1_account_files = PathBuf::from("../fixtures/accounts/v1/server");
    let v1_identity_src = v1_account_files.join(IDENTITY_DIR);
    let v1_remote_src = v1_account_files.join(REMOTE_DIR);

    let v1_identity_dest = data_dir.join(IDENTITY_DIR);
    let v1_remote_dest = data_dir.join(REMOTE_DIR);

    // If we disable the teardown we still want the test to work
    if v1_identity_dest.exists() {
        std::fs::remove_dir_all(&v1_identity_dest)?;
    }
    if v1_remote_dest.exists() {
        std::fs::remove_dir_all(&v1_remote_dest)?;
    }

    // Copy fixtures into test location
    copy_dir(&v1_identity_src, &v1_identity_dest)?;
    copy_dir(&v1_remote_src, &v1_remote_dest)?;

    // Upgrade the file system accounts into the db
    let options = UpgradeOptions {
        server: true,
        dry_run: false,
        ..Default::default()
    };
    let result = upgrade_accounts(data_dir, options).await?;
    assert!(result.database_file.exists());

    teardown(TEST_ID).await;

    Ok(())
}
