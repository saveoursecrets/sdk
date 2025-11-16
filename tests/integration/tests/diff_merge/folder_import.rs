use sos_test_utils::{copy_account, mock, setup, teardown};
use anyhow::Result;
use sos_account::{Account, FolderCreate, LocalAccount};
use sos_client_storage::NewFolderOptions;
use sos_protocol::diff;
use sos_sdk::prelude::*;
use sos_sync::{
    Merge, MergeOutcome, SyncStorage, TrackedAccountChange,
    TrackedFolderChange,
};
use sos_test_utils::make_client_backend;
use sos_vfs as vfs;

/// Tests creating a diff and merging an import folder
/// event without any networking.
#[tokio::test]
async fn diff_merge_folder_import() -> Result<()> {
    const TEST_ID: &str = "diff_merge_folder_import";
    //sos_test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 3).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_client(&data_dir);
    let data_dir_export = dirs.clients.remove(0);
    let export_paths = Paths::new_client(&data_dir_export);
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

    // Copy the initial account disc state to an account
    // we will use to export the folder and export the folder
    // to a vault file.
    //
    // We use a temp account so we don't create events other
    // then the import event in the accounts we want to test.
    copy_account(&data_dir, &data_dir_export)?;
    let mut temp = LocalAccount::new_unauthenticated(
        account_id,
        make_client_backend(&export_paths).await?,
    )
    .await?;
    temp.sign_in(&key).await?;
    let FolderCreate {
        folder: summary, ..
    } = temp
        .create_folder(NewFolderOptions::new("new_folder".to_owned()))
        .await?;
    let (folder_password, _) = generate_passphrase()?;
    let folder_key: AccessKey = folder_password.into();
    let exported = data_dir_export.join("exported.vault");
    temp.export_folder(&exported, summary.id(), folder_key.clone(), false)
        .await?;
    assert!(vfs::try_exists(&exported).await?);

    // Import the buffer into local
    let buffer = vfs::read(&exported).await?;
    local
        .import_folder_buffer(&buffer, folder_key, false)
        .await?;

    // Sign in on the remote account
    let mut remote = LocalAccount::new_unauthenticated(
        account_id,
        make_client_backend(&merge_paths).await?,
    )
    .await?;
    remote.sign_in(&key).await?;

    assert_ne!(local.sync_status().await?, remote.sync_status().await?);

    let remote_status = remote.sync_status().await?;
    let (needs_sync, _status, diff) =
        diff::<_, sos_remote_sync::Error>(&local, remote_status).await?;
    assert!(needs_sync);

    // Merge the changes
    let mut outcome = MergeOutcome::default();
    remote.merge(diff, &mut outcome).await?;
    assert_eq!(local.sync_status().await?, remote.sync_status().await?);

    assert_eq!(2, outcome.changes);
    assert!(matches!(
        outcome.tracked.identity.first().unwrap(),
        TrackedFolderChange::Created(_)
    ));
    // Account tracked a folder created event
    assert!(matches!(
        outcome.tracked.account.first().unwrap(),
        TrackedAccountChange::FolderCreated(_)
    ));

    // Should have the additional folder now
    let folders = remote.list_folders().await?;
    assert_eq!(2, folders.len());

    // Open the folder for writing
    remote.open_folder(summary.id()).await?;

    // Check we can write to the new folder
    let (meta, secret) = mock::note("note", TEST_ID);
    remote
        .create_secret(meta, secret, Default::default())
        .await?;

    teardown(TEST_ID).await;

    Ok(())
}
