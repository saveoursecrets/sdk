mod backup_archive_client;
mod backup_archive_server;

mod upgrade_client;
mod upgrade_server;

pub use sos_test_utils as test_utils;

use anyhow::Result;
use sos_core::constants::{IDENTITY_DIR, LOCAL_DIR, REMOTE_DIR};
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
