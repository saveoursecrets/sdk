use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests the basic secret lifecycle; create, read, update
/// and delete.
#[tokio::test]
async fn integration_secret_lifecycle() -> Result<()> {
    const TEST_ID: &str = "secret_lifecycle";
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

    // Create secret
    let (meta, secret) = mock::note("note", TEST_ID);
    let SecretChange { id, folder, .. } = account
        .create_secret(meta, secret, Default::default())
        .await?;
    assert_eq!(&default_folder, &folder);

    // Read secret
    let (data, _) = account.read_secret(&id, Default::default()).await?;
    assert_eq!(&id, data.id());
    assert_eq!("note", data.meta().label());

    // Update secret
    let (meta, secret) = mock::note("note_edited", TEST_ID);
    account
        .update_secret(
            &id,
            meta.clone(),
            Some(secret),
            Default::default(),
            None,
        )
        .await?;
    let (data, _) = account.read_secret(&id, Default::default()).await?;
    assert_eq!(&meta, data.meta());
    assert_eq!("note_edited", data.meta().label());

    // Delete
    account.delete_secret(&id, Default::default()).await?;

    teardown(TEST_ID).await;

    Ok(())
}
