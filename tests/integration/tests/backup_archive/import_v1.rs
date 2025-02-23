use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_account::{Account, LocalAccount};
use sos_backend::BackendTarget;
use sos_database::open_file;
use sos_filesystem::archive::{
    AccountBackup, ExtractFilesLocation, Inventory, RestoreOptions,
};
use sos_sdk::prelude::{vfs, Paths};
use tokio::io::BufReader;

/// Test importing from a v1 backup archive.
#[tokio::test]
async fn backup_import_v1() -> Result<()> {
    const TEST_ID: &str = "backup_import_v1";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(Some(data_dir.clone())).await?;

    let archive =
        "../fixtures/backups/v1/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";
    let reader = vfs::File::open(archive).await?;
    let inventory: Inventory =
        AccountBackup::restore_archive_inventory(BufReader::new(reader))
            .await?;

    let paths = Paths::new_client(&data_dir)
        .with_account_id(&inventory.manifest.account_id);
    paths.ensure().await?;

    let options = RestoreOptions {
        selected: inventory.vaults,
        files_dir: Some(ExtractFilesLocation::Path(
            paths.files_dir().to_owned(),
        )),
    };

    let target = if paths.is_using_db() {
        let client = open_file(paths.database_file()).await?;
        BackendTarget::Database(paths.clone(), client)
    } else {
        BackendTarget::FileSystem(paths.clone())
    };

    LocalAccount::import_backup_archive(
        &archive,
        options,
        &target,
        Some(data_dir.clone()),
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
