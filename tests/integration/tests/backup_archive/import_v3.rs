use anyhow::Result;
use sos_backend::{
    archive::{self, read_backup_archive_manifest},
    BackendTarget,
};
use sos_core::{AccountId, Paths};
use sos_database::open_file;
use sos_test_utils::{setup, teardown};

/// Test importing from a v3 backup archive.
///
/// Version 3 backup archives are only compatible with
/// the database backend.
#[tokio::test]
async fn backup_import_v3() -> Result<()> {
    const TEST_ID: &str = "backup_import_v3";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(&data_dir).await?;

    let archive =
        "../fixtures/backups/v3/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";

    let paths = Paths::new_client(&data_dir);
    let client = open_file(paths.database_file()).await?;
    let target = BackendTarget::Database(paths.clone(), client);

    let accounts = archive::import_backup_archive(&archive, &target).await?;
    assert_eq!(1, accounts.len());

    teardown(TEST_ID).await;

    Ok(())
}

/// Test importing a specific account in a v3 backup archive.
///
/// Version 3 backup archives are only compatible with
/// the database backend.
#[tokio::test]
async fn backup_import_v3_account() -> Result<()> {
    const TEST_ID: &str = "backup_import_v3_account";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(&data_dir).await?;

    let archive = "../fixtures/backups/v3/multiple-accounts.zip";

    let account_id: AccountId =
        "0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac".parse()?;
    let paths = Paths::new_client(&data_dir);
    let client = open_file(paths.database_file()).await?;
    let target = BackendTarget::Database(paths.clone(), client);

    let accounts = vec![account_id];
    let manifest = read_backup_archive_manifest(&archive).await?;
    let accounts = archive::import_backup_archive_accounts(
        &archive,
        &target,
        manifest,
        Some(&accounts),
    )
    .await?;
    assert_eq!(1, accounts.len());

    teardown(TEST_ID).await;

    Ok(())
}
