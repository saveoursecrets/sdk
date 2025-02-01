use super::{assert_import_archive, prepare_server_for_upgrade};
use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_core::Paths;
use sos_database::{
    archive,
    async_sqlite::rusqlite::Connection,
    upgrader::{upgrade_accounts, UpgradeOptions},
};
use sos_external_files::list_external_blobs;

/// Create and import a backup archive for server-side database storage.
///
/// We don't have a database account builder yet so we perform
/// an upgrade to mock the database storage for the backup archive.
#[tokio::test]
async fn database_import_archive_server() -> Result<()> {
    const TEST_ID: &str = "database_import_archive_server";
    // crate::test_utils::init_tracing();

    let dirs = setup(TEST_ID, 0).await?;
    prepare_server_for_upgrade(&dirs)?;

    let paths = Paths::new_global_server(&dirs.test_dir);

    // Upgrade the file system accounts into the db
    let options = UpgradeOptions {
        paths: paths.clone(),
        dry_run: false,
        ..Default::default()
    };
    let result = upgrade_accounts(dirs.test_dir.clone(), options).await?;
    assert!(result.database_file.exists());

    // Create a backup archive.
    let zip = dirs.test_dir.join("backup.zip");
    let paths = Paths::new_global_server(dirs.test_dir.clone());
    let source_db = Connection::open(result.database_file)?;
    archive::create_backup_archive(&source_db, &paths, &zip).await?;

    assert!(zip.exists());

    // Import the archive
    assert_import_archive(&paths, &zip).await?;

    teardown(TEST_ID).await;

    Ok(())
}
