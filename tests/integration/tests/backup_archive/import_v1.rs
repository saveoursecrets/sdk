use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_account::{Account, LocalAccount};
use sos_backend::BackendTarget;
use sos_database::open_file;
use sos_sdk::prelude::Paths;

/// Test importing from a v1 backup archive.
#[tokio::test]
async fn backup_import_v1() -> Result<()> {
    const TEST_ID: &str = "backup_import_v1";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(&data_dir).await?;

    let archive =
        "../fixtures/backups/v1/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";

    let paths = Paths::new_client(&data_dir);
    let target = if paths.is_using_db() {
        let client = open_file(paths.database_file()).await?;
        BackendTarget::Database(paths.clone(), client)
    } else {
        BackendTarget::FileSystem(paths.clone())
    };

    let accounts =
        LocalAccount::import_backup_archive(&archive, &target).await?;

    assert_eq!(1, accounts.len());

    teardown(TEST_ID).await;

    Ok(())
}
