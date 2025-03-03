use anyhow::Result;
use sos_backend::{archive, BackendTarget};
use sos_core::Paths;
use sos_test_utils::{setup, teardown};

/// Test importing from a v2 backup archive.
///
/// Version 2 archives are only compatible with
/// the file system backend.
#[tokio::test]
async fn backup_import_v2() -> Result<()> {
    const TEST_ID: &str = "backup_import_v2";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(&data_dir).await?;

    let archive =
        "../fixtures/backups/v2/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";
    let paths = Paths::new_client(&data_dir);
    let target = BackendTarget::FileSystem(paths);
    let accounts = archive::import_backup_archive(&archive, &target).await?;
    assert_eq!(1, accounts.len());

    teardown(TEST_ID).await;

    Ok(())
}
