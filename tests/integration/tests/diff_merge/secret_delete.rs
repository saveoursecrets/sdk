use crate::test_utils::{copy_account, mock, setup, teardown};
use anyhow::Result;
use sos_account::{Account, LocalAccount, SecretChange};
use sos_core::{crypto::AccessKey, ErrorExt, Paths};
use sos_password::diceware::generate_passphrase;
use sos_protocol::diff;
use sos_sync::MergeOutcome;
use sos_sync::{Merge, SyncStorage};
use sos_test_utils::make_client_backend;

/// Tests creating a diff and merging a delete secret
/// event without any networking.
#[tokio::test]
async fn diff_merge_secret_delete() -> Result<()> {
    const TEST_ID: &str = "diff_merge_secret_delete";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 2).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_global(&data_dir);
    let data_dir_merge = dirs.clients.remove(0);
    let merge_paths = Paths::new_global(&data_dir_merge);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut local = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        make_client_backend(&paths),
        Some(data_dir.clone()),
    )
    .await?;

    let key: AccessKey = password.clone().into();
    local.sign_in(&key).await?;
    let default_folder = local.default_folder().await.unwrap();
    let account_id = local.account_id().clone();

    // Copy the initial account disc state
    copy_account(&data_dir, &data_dir_merge)?;

    // Sign in on the other account
    let mut remote = LocalAccount::new_unauthenticated(
        account_id,
        make_client_backend(&merge_paths),
    )
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
    let (needs_sync, _status, diff) =
        diff::<_, sos_remote_sync::Error>(&local, remote_status).await?;
    assert!(needs_sync);

    // Merge the changes
    let mut outcome = MergeOutcome::default();
    remote.merge(diff, &mut outcome).await?;
    assert_eq!(local.sync_status().await?, remote.sync_status().await?);

    assert_eq!(2, outcome.changes);
    // Collection of changes exists but the collection is
    // empty because the create event followed by a
    // delete event was normalized
    assert!(outcome.tracked.folders.get(default_folder.id()).is_none());

    // Check we can't read the secret
    let err = remote.read_secret(&id, None).await.err().unwrap();
    assert!(err.is_secret_not_found());

    // Check we can't find it in the search index
    let documents = remote.query_map("note", Default::default()).await?;
    assert_eq!(0, documents.len());

    teardown(TEST_ID).await;

    Ok(())
}
