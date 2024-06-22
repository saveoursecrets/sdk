use crate::test_utils::{copy_account, mock, setup, teardown};
use anyhow::Result;
use sos_net::{
    protocol::{diff, MaybeDiff, Merge, MergeOutcome, SyncStorage},
    sdk::prelude::*,
};

/// Tests creating a diff and merging a move secret
/// event without any networking.
#[tokio::test]
#[ignore]
async fn diff_merge_secret_move() -> Result<()> {
    const TEST_ID: &str = "diff_merge_secret_move";
    crate::test_utils::init_tracing();

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
    let default_folder = local.default_folder().await.unwrap();

    // Copy the initial account disc state
    copy_account(&data_dir, &data_dir_merge)?;

    // Sign in on the other account
    let mut remote =
        LocalAccount::new_unauthenticated(address, Some(data_dir_merge))
            .await?;
    remote.sign_in(&key).await?;

    // Create a secret in the default folder.
    let (meta, secret) = mock::note("note", TEST_ID);
    let SecretChange { id, .. } = local
        .create_secret(meta.clone(), secret.clone(), Default::default())
        .await?;

    // Create a new folder
    let FolderCreate {
        folder: summary, ..
    } = local.create_folder("new_folder".to_owned()).await?;

    // Move the secret
    let SecretMove { id: new_id, .. } = local
        .move_secret(&id, &default_folder, &summary, Default::default())
        .await?;

    assert_ne!(local.sync_status().await?, remote.sync_status().await?);

    let remote_status = remote.sync_status().await?;
    let (needs_sync, _status, diff) = diff(&local, remote_status).await?;
    assert!(needs_sync);

    println!("default folder id: {}", default_folder.id());
    println!("new folder id: {}", summary.id());

    // println!("Merging the changes: {:#?}", diff);

    /*
    for (id, folder_diff) in &diff.folders {
        if let MaybeDiff::Diff(diff) = folder_diff {
            println!(
                "{} {:#?}",
                id,
                diff.patch.records().first().map(|r| r.time())
            );
        }
    }
    */

    // Merge the changes
    remote.merge(diff, &mut MergeOutcome::default()).await?;
    assert_eq!(local.sync_status().await?, remote.sync_status().await?);

    // Should have the additional folder now
    let folders = remote.list_folders().await?;
    assert_eq!(2, folders.len());

    // Check we can't read the secret in the source folder (from)
    let result = remote
        .read_secret(&new_id, Some(default_folder.clone()))
        .await;
    assert!(matches!(result, Err(Error::SecretNotFound(_))));

    // Check we can read it in the destination folder (to)
    remote.open_folder(&summary).await?;
    let (data, _) =
        remote.read_secret(&new_id, Some(summary.clone())).await?;
    assert_eq!(&meta, data.meta());
    assert_eq!(&secret, data.secret());

    teardown(TEST_ID).await;

    Ok(())
}
