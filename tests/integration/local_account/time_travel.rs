use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

const TEST_ID: &str = "time_travel";

/// Tests creating a detached view at a point in time of a
/// folder's commit history.
#[tokio::test]
async fn integration_time_travel() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
    )
    .await?;

    let key: AccessKey = password.clone().into();
    account.sign_in(&key).await?;
    let default_folder = account.default_folder().await.unwrap();

    // Create the first secret
    let (meta, secret) = mock::note("note1", TEST_ID);
    let (id1, _, _, _) = account
        .create_secret(meta, secret, Default::default())
        .await?;

    // Store the state so we can backtrack
    let (commit, _) = account.commit_state(&default_folder).await?;

    // Create another secret
    let (meta, secret) = mock::note("note2", TEST_ID);
    let (id2, _, _, _) = account
        .create_secret(meta, secret, Default::default())
        .await?;

    // Create the detached view and assert
    let view = account.detached_view(&default_folder, commit).await?;
    let secret1 = view.keeper().read_secret(&id1).await?;
    let secret2 = view.keeper().read_secret(&id2).await?;
    assert!(secret1.is_some());
    assert!(secret2.is_none());

    teardown(TEST_ID).await;

    Ok(())
}
