use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

const TEST_ID: &str = "diff_merge_create_folder";

use super::copy_account;

/// Tests creating a diff and merging a create folder
/// event without any networking.
#[tokio::test]
async fn integration_diff_merge_create_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 2).await?;
    let data_dir = dirs.clients.remove(0);
    let data_dir_merge = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut local = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let key: AccessKey = password.clone().into();
    local.sign_in(&key).await?;
    let address = local.address().clone();

    // Copy the initial account disc state
    copy_account(&data_dir, &data_dir_merge)?;

    // Sign in on the other account
    let mut remote = LocalAccount::new_unauthenticated(
        address,
        Some(data_dir_merge),
        None,
    )
    .await?;
    remote.sign_in(&key).await?;

    // Create a new folder
    let (summary, _, _) =
        local.create_folder("new_folder".to_owned()).await?;

    let remote_status = remote.sync_status().await?;
    let (needs_sync, _status, diff) = diff(&local, remote_status).await?;
    assert!(needs_sync);

    // Merge the changes
    remote.merge(&diff).await?;

    // Should have the additional folder now
    let folders = remote.list_folders().await?;
    assert_eq!(2, folders.len());

    // Open the folder for writing
    remote.open_folder(&summary).await?;

    // Check we can write to the new folder
    let (meta, secret) = mock::note("note", TEST_ID);
    remote
        .create_secret(meta, secret, Default::default())
        .await?;

    teardown(TEST_ID).await;

    Ok(())
}
