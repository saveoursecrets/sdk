use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_database::importer::import_accounts;
use sos_sdk::prelude::{
    vfs, Account, AccountBackup, Inventory, LocalAccount, Paths,
    RestoreOptions,
};
use tokio::io::BufReader;

#[tokio::test]
async fn database_importer() -> Result<()> {
    const TEST_ID: &str = "database_importer";

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(Some(data_dir.clone())).await?;

    // Prepare to import to database file
    // by restoring an account from a backup archive fixture
    let archive =
        "../../fixtures/backups/v2/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";
    let reader = vfs::File::open(archive).await?;
    let inventory: Inventory =
        AccountBackup::restore_archive_inventory(BufReader::new(reader))
            .await?;
    let options = RestoreOptions {
        selected: inventory.vaults,
        ..Default::default()
    };
    LocalAccount::import_backup_archive(
        &archive,
        options,
        Some(data_dir.clone()),
    )
    .await?;

    // Import the file system accounts into the db
    import_accounts(data_dir).await?;

    teardown(TEST_ID).await;

    Ok(())
}
