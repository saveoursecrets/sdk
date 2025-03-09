use anyhow::Result;
use sos_backend::{archive, BackendTarget};
use sos_core::Paths;
use sos_database::open_file;
use sos_test_utils::{setup, teardown};

/// Test incompatibility between a v1 backup archive
/// and a database backend.
#[tokio::test]
async fn backup_incompatible_v1_db() -> Result<()> {
    const TEST_ID: &str = "backup_incompatible_v1_db";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let archive =
        "../fixtures/backups/v1/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";

    let paths = Paths::new_client(&data_dir);
    let client = open_file(paths.database_file()).await?;
    let target = BackendTarget::Database(paths.clone(), client);

    let result = archive::import_backup_archive(&archive, &target).await;
    assert!(matches!(
        result.err().unwrap(),
        sos_backend::Error::BackupArchiveUpgradeRequired(_, _, _)
    ));

    teardown(TEST_ID).await;

    Ok(())
}

/// Test incompatibility between a v2 backup archive
/// and a database backend.
#[tokio::test]
async fn backup_incompatible_v2_db() -> Result<()> {
    const TEST_ID: &str = "backup_incompatible_v2_db";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let archive =
        "../fixtures/backups/v2/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";

    let paths = Paths::new_client(&data_dir);
    let client = open_file(paths.database_file()).await?;
    let target = BackendTarget::Database(paths.clone(), client);

    let result = archive::import_backup_archive(&archive, &target).await;
    assert!(matches!(
        result.err().unwrap(),
        sos_backend::Error::BackupArchiveUpgradeRequired(_, _, _)
    ));

    teardown(TEST_ID).await;

    Ok(())
}

/// Test incompatibility between a v3 backup archive
/// and a filesystem backend.
#[tokio::test]
async fn backup_incompatible_v3_fs() -> Result<()> {
    const TEST_ID: &str = "backup_incompatible_v3_fs";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(&data_dir).await?;

    let archive =
        "../fixtures/backups/v3/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";

    let paths = Paths::new_client(&data_dir);
    let target = BackendTarget::FileSystem(paths.clone());
    let result = archive::import_backup_archive(&archive, &target).await;
    assert!(matches!(
        result.err().unwrap(),
        sos_backend::Error::IncompatibleBackupArchive(_, _, _)
    ));

    teardown(TEST_ID).await;

    Ok(())
}
