use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests updating the search index when we update secrets.
#[tokio::test]
async fn integration_search_update_secret() -> Result<()> {
    const TEST_ID: &str = "search_update_secret";
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

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    // Create a secret
    let (meta, secret) = mock::note("note", TEST_ID);
    let SecretChange { id, .. } = account
        .create_secret(meta, secret, Default::default())
        .await?;

    // Can find the new secret
    let documents = account.query_map("note", Default::default()).await?;
    assert_eq!(1, documents.len());

    // Update with a new label
    let (meta, secret) = mock::note("updated", TEST_ID);
    account
        .update_secret(&id, meta, Some(secret), Default::default(), None)
        .await?;

    // Check we can't find with the old label
    let documents = account.query_map("note", Default::default()).await?;
    assert_eq!(0, documents.len());

    // Can find the updated secret
    let documents = account.query_map("upda", Default::default()).await?;
    assert_eq!(1, documents.len());

    teardown(TEST_ID).await;

    Ok(())
}
