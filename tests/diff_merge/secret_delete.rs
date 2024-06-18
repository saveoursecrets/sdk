use crate::test_utils::{copy_account, mock, setup, teardown};
use anyhow::Result;
use sos_net::{
    sdk::prelude::*,
    sync::{diff, Merge, MergeOutcome, SyncStorage},
};

/// Tests creating a diff and merging a delete secret
/// event without any networking.
#[tokio::test]
async fn diff_merge_secret_delete() -> Result<()> {
    const TEST_ID: &str = "diff_merge_secret_delete";
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

    // Create a new secret
    let (meta, secret) = mock::note("note", TEST_ID);
    let SecretChange { id, .. } = local
        .create_secret(meta.clone(), secret.clone(), Default::default())
        .await?;

    local.delete_secret(&id, Default::default()).await?;

    assert_ne!(local.sync_status().await?, remote.sync_status().await?);

    let remote_status = remote.sync_status().await?;
    let (needs_sync, _status, diff) = diff(&local, remote_status).await?;
    assert!(needs_sync);

    // Merge the changes
    remote.merge(diff, &mut MergeOutcome::default()).await?;
    assert_eq!(local.sync_status().await?, remote.sync_status().await?);

    // Check we can't read the secret
    let result = remote.read_secret(&id, None).await;
    assert!(matches!(result, Err(Error::SecretNotFound(_))));

    // Check we can't find it in the search index
    let documents = remote.query_map("note", Default::default()).await?;
    assert_eq!(0, documents.len());

    teardown(TEST_ID).await;

    Ok(())
}
