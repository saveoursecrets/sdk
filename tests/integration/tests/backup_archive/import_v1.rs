use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_account::{
    archive::RestoreOptions,
    archive::{AccountBackup, ExtractFilesLocation, Inventory},
    Account, LocalAccount,
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

    let user_paths = Paths::new(
        data_dir.clone(),
        inventory.manifest.account_id.to_string(),
    );
    user_paths.ensure().await?;

    let options = RestoreOptions {
        selected: inventory.vaults,
        files_dir: Some(ExtractFilesLocation::Path(
            user_paths.files_dir().to_owned(),
        )),
    };

    LocalAccount::import_backup_archive(
        &archive,
        options,
        Some(data_dir.clone()),
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
