use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use maplit2::{hashmap, hashset};
use sos_net::sdk::{
    account::{
        search::{ArchiveFilter, DocumentView, QueryFilter},
        LocalAccount, UserPaths,
    },
    passwd::diceware::generate_passphrase,
    vault::secret::{IdentityKind, SecretType},
};

const TEST_ID: &str = "search_favorites";

/// Tests the favorites view.
#[tokio::test]
async fn integration_search_favorites() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    UserPaths::scaffold(Some(data_dir.clone())).await?;
    UserPaths::new_global(data_dir.clone());

    let (mut account, new_account) = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let default_folder = new_account.default_folder();
    account.sign_in(password.clone()).await?;
    account.open_folder(&default_folder).await?;
    
    // Create a secret
    let (meta, secret) = mock::login(
        "login", TEST_ID, generate_passphrase()?.0);
    let (id, _, _, _) = account.create_secret(
        meta, secret, Default::default()).await?;

    // No favorites yet
    let documents = account
        .query_view(vec![DocumentView::Favorites], None)
        .await?;
    assert_eq!(0, documents.len());
    
    // Mark a secret as favorite
    let (mut data, _) = account.read_secret(&id, None).await?;
    data.meta_mut().set_favorite(true);
    let (_, _, _, _) = account
        .update_secret(
            &id,
            data.into(),
            None,
            Default::default(),
            None,
        )
        .await?;

    // Should have a favorite now
    let documents = account
        .query_view(vec![DocumentView::Favorites], None)
        .await?;
    assert_eq!(1, documents.len());

    // No longer a favorite
    let (mut data, _) = account.read_secret(&id, None).await?;
    data.meta_mut().set_favorite(false);
    let (_, _, _, _) = account
        .update_secret(
            &id,
            data.into(),
            None,
            Default::default(),
            None,
        )
        .await?;

    // Not in the favorites view anymore 
    let documents = account
        .query_view(vec![DocumentView::Favorites], None)
        .await?;
    assert_eq!(0, documents.len());

    teardown(TEST_ID).await;

    Ok(())
}
