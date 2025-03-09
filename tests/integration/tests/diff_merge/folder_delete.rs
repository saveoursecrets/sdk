use crate::test_utils::{copy_account, setup, teardown};
use anyhow::Result;
use sos_account::{Account, FolderCreate, LocalAccount};
use sos_client_storage::NewFolderOptions;
use sos_protocol::diff;
use sos_sdk::prelude::*;
use sos_sync::{Merge, MergeOutcome, SyncStorage};
use sos_test_utils::make_client_backend;

/// Tests creating a diff and merging a delete folder
/// event without any networking.
#[tokio::test]
async fn diff_merge_folder_delete() -> Result<()> {
    const TEST_ID: &str = "diff_merge_folder_delete";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 2).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_client(&data_dir);
    let data_dir_merge = dirs.clients.remove(0);
    let merge_paths = Paths::new_client(&data_dir_merge);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut local = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        make_client_backend(&paths).await?,
    )
    .await?;

    let key: AccessKey = password.clone().into();
    local.sign_in(&key).await?;
    let account_id = local.account_id().clone();

    // Copy the initial account disc state
    copy_account(&data_dir, &data_dir_merge)?;

    // Sign in on the other account
    let mut remote = LocalAccount::new_unauthenticated(
        account_id,
        make_client_backend(&merge_paths).await?,
    )
    .await?;
    remote.sign_in(&key).await?;

    // Create a new folder
    let FolderCreate {
        folder: summary, ..
    } = local
        .create_folder(NewFolderOptions::new("new_folder".to_owned()))
        .await?;

    // Delete the folder
    local.delete_folder(summary.id()).await?;

    assert_ne!(local.sync_status().await?, remote.sync_status().await?);

    let remote_status = remote.sync_status().await?;
    let (needs_sync, _status, diff) =
        diff::<_, sos_remote_sync::Error>(&local, remote_status).await?;
    assert!(needs_sync);

    // Merge the changes
    let mut outcome = MergeOutcome::default();
    remote.merge(diff, &mut outcome).await?;
    assert_eq!(local.sync_status().await?, remote.sync_status().await?);

    assert_eq!(4, outcome.changes);
    // Events will be normalized away (create folder followed by deletion)
    assert!(outcome.tracked.identity.is_empty());
    assert!(outcome.tracked.account.is_empty());

    // Should have the same number of folders
    let folders = remote.list_folders().await?;
    assert_eq!(1, folders.len());

    teardown(TEST_ID).await;

    Ok(())
}
