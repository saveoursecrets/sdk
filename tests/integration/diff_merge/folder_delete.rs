use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

const TEST_ID: &str = "diff_merge_folder_delete";

use super::copy_account;

/// Tests creating a diff and merging a delete folder
/// event without any networking.
#[tokio::test]
async fn integration_diff_merge_folder_delete() -> Result<()> {
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
    )
    .await?;

    let key: AccessKey = password.clone().into();
    local.sign_in(&key).await?;
    let address = local.address().clone();

    // Copy the initial account disc state
    copy_account(&data_dir, &data_dir_merge)?;

    // Sign in on the other account
    let mut remote =
        LocalAccount::new_unauthenticated(address, Some(data_dir_merge))
            .await?;
    remote.sign_in(&key).await?;

    // Create a new folder
    let (summary, _, _) =
        local.create_folder("new_folder".to_owned()).await?;

    // Delete the folder
    local.delete_folder(&summary).await?;

    assert_ne!(local.sync_status().await?, remote.sync_status().await?);

    let remote_status = remote.sync_status().await?;
    let (needs_sync, _status, diff) = diff(&local, remote_status).await?;
    assert!(needs_sync);

    // Merge the changes
    remote.merge(&diff).await?;
    assert_eq!(local.sync_status().await?, remote.sync_status().await?);

    // Should have the same number of folders
    let folders = remote.list_folders().await?;
    assert_eq!(1, folders.len());

    teardown(TEST_ID).await;

    Ok(())
}
