use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests the favorites view.
#[tokio::test]
async fn local_search_favorites() -> Result<()> {
    const TEST_ID: &str = "search_favorites";
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
    let (meta, secret) =
        mock::login("login", TEST_ID, generate_passphrase()?.0);
    let SecretChange { id, .. } = account
        .create_secret(meta, secret, Default::default())
        .await?;

    // No favorites yet
    let documents = account
        .query_view(vec![DocumentView::Favorites], None)
        .await?;
    assert_eq!(0, documents.len());

    // Mark a secret as favorite
    let (mut data, _) = account.read_secret(&id, None).await?;
    data.meta_mut().set_favorite(true);
    account
        .update_secret(&id, data.into(), None, Default::default(), None)
        .await?;

    // Should have a favorite now
    let documents = account
        .query_view(vec![DocumentView::Favorites], None)
        .await?;
    assert_eq!(1, documents.len());

    // No longer a favorite
    let (mut data, _) = account.read_secret(&id, None).await?;
    data.meta_mut().set_favorite(false);
    account
        .update_secret(&id, data.into(), None, Default::default(), None)
        .await?;

    // Not in the favorites view anymore
    let documents = account
        .query_view(vec![DocumentView::Favorites], None)
        .await?;
    assert_eq!(0, documents.len());

    teardown(TEST_ID).await;

    Ok(())
}
