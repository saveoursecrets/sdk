mod backup_archive_client;
mod backup_archive_server;

mod import_archive_client;
mod import_archive_server;

mod upgrade_client;
mod upgrade_server;

pub use sos_test_utils as test_utils;

use anyhow::Result;
use sos_core::{
    constants::{IDENTITY_DIR, LOCAL_DIR, REMOTE_DIR},
    Paths,
};
use sos_database::archive;
use sos_external_files::list_external_files;
use std::path::PathBuf;
use test_utils::{copy_dir, TestDirs};

pub fn prepare_client_for_upgrade(dirs: &TestDirs) -> Result<()> {
    let data_dir = &dirs.test_dir;

    let v1_account_files = PathBuf::from("../fixtures/accounts/v1/client");
    let v1_identity_src = v1_account_files.join(IDENTITY_DIR);
    let v1_local_src = v1_account_files.join(LOCAL_DIR);

    let v1_identity_dest = data_dir.join(IDENTITY_DIR);
    let v1_local_dest = data_dir.join(LOCAL_DIR);

    // If we disable the teardown we still want the test to work
    if v1_identity_dest.exists() {
        std::fs::remove_dir_all(&v1_identity_dest)?;
    }
    if v1_local_dest.exists() {
        std::fs::remove_dir_all(&v1_local_dest)?;
    }

    // Copy fixtures into test location
    copy_dir(&v1_identity_src, &v1_identity_dest)?;
    copy_dir(&v1_local_src, &v1_local_dest)?;

    Ok(())
}

pub fn prepare_server_for_upgrade(dirs: &TestDirs) -> Result<()> {
    let data_dir = &dirs.test_dir;

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

    Ok(())
}

pub async fn assert_import_archive(
    paths: &Paths,
    zip: &PathBuf,
) -> Result<()> {
    // Delete the database and blobs storage to quickly
    // mock the account not existing
    std::fs::remove_file(paths.database_file())?;
    std::fs::remove_dir_all(paths.blobs_dir())?;

    // let mut target_db = Connection::open(paths.database_file())?;
    let mut import =
        archive::import_backup_archive(paths.database_file(), paths, zip)
            .await?;

    // Run migrations on the source to ensure it's schema is up to date.
    //
    // We don't need to do this for the test as we just created the archive
    // but we have it here to illustrate best practices.
    import.migrate_source()?;

    // Run migrations on the target database to ensure schema is up to date
    import.migrate_target()?;

    // Just deleted the db so no target accounts yet
    assert!(import.list_target_accounts()?.is_empty());

    // List accounts in the backup archive
    let source_accounts = import.list_source_accounts()?;

    // We know the backup archive has a single account so import it
    import
        .import_account(source_accounts.first().unwrap())
        .await?;

    // Should have one target account in the db
    let mut target_accounts = import.list_target_accounts()?;
    assert!(!target_accounts.is_empty());
    let account_record = target_accounts.remove(0);

    // Should have some extracted external file blobs
    let account_paths =
        paths.with_account_id(account_record.identity.account_id());
    let external_blobs = list_external_files(&account_paths).await?;
    assert!(!external_blobs.is_empty());

    Ok(())
}
