use anyhow::Result;
use sos_account::{Account, LocalAccount};
use sos_backend::BackendTarget;
use sos_core::Paths;
use sos_database::open_file;
use sos_database_upgrader::archive::upgrade_backup_archive;
use sos_test_utils::{setup, teardown};
use std::{path::Path, sync::Arc};

/// Test upgrading from a v1 backup archive and importing
/// the converted archive.
#[tokio::test]
async fn backup_upgrade_import_v1() -> Result<()> {
    const TEST_ID: &str = "backup_upgrade_import_v1";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let archive =
        "../fixtures/backups/v1/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";
    let paths = Paths::new_client(&data_dir);
    let upgrade = paths.documents_dir().join("backup-upgrade.zip");
    assert_upgrade_import(paths, archive, upgrade).await?;

    teardown(TEST_ID).await;
    Ok(())
}

/// Test upgrading from a v2 backup archive and importing
/// the converted archive.
#[tokio::test]
async fn backup_upgrade_import_v2() -> Result<()> {
    const TEST_ID: &str = "backup_upgrade_import_v2";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let archive =
        "../fixtures/backups/v2/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";
    let paths = Paths::new_client(&data_dir);
    let upgrade = paths.documents_dir().join("backup-upgrade.zip");
    assert_upgrade_import(paths, archive, upgrade).await?;

    teardown(TEST_ID).await;
    Ok(())
}

async fn assert_upgrade_import(
    paths: Arc<Paths>,
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<()> {
    let client = open_file(paths.database_file()).await?;
    let target = BackendTarget::Database(paths.clone(), client);
    upgrade_backup_archive(input.as_ref(), output.as_ref()).await?;
    let accounts =
        LocalAccount::import_backup_archive(output.as_ref(), &target).await?;
    assert_eq!(1, accounts.len());

    let target =
        target.with_account_id(accounts.get(0).unwrap().account_id());
    let files = target.list_files().await?;
    assert!(files.len() > 0);

    Ok(())
}
