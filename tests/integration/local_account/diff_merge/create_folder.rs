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

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let key: AccessKey = password.clone().into();
    account.sign_in(&key).await?;
    let address = account.address().clone();
    let default_folder = account.default_folder().await.unwrap();

    // Copy the initial account disc state
    copy_account(&data_dir, &data_dir_merge)?;
    
    // Sign in on the other account
    let mut account_merge = LocalAccount::new_unauthenticated(
        address,
        Some(data_dir_merge),
        None,
    )
    .await?;
    account_merge.sign_in(&key).await?;

    // Create a new folder
    account.create_folder("new_folder".to_owned()).await?;
    
    let remote_status = account_merge.sync_status().await?;
    let (needs_sync, local_status, local_diff) =
        diff(&account, remote_status).await?;

    assert!(needs_sync);

    teardown(TEST_ID).await;

    Ok(())
}
