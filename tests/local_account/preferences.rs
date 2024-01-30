use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests the account preferences.
#[tokio::test]
async fn local_preferences() -> Result<()> {
    const TEST_ID: &str = "preferences";
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

    let identity = account.public_identity().await?.clone();
    let identities = vec![identity];

    CachedPreferences::initialize(&identities, Some(data_dir.clone()))
        .await?;

    // Create preferences
    CachedPreferences::set(
        account.address(),
        "mock.bool".to_owned(),
        true.into(),
    )
    .await?;

    CachedPreferences::set(
        account.address(),
        "mock.int".to_owned(),
        (-15 as i64).into(),
    )
    .await?;

    CachedPreferences::set(
        account.address(),
        "mock.double".to_owned(),
        (3.14 as f64).into(),
    )
    .await?;
    CachedPreferences::set(
        account.address(),
        "mock.string".to_owned(),
        "message".to_owned().into(),
    )
    .await?;
    let list = vec!["item-1".to_owned(), "item-2".to_owned()];
    CachedPreferences::set(
        account.address(),
        "mock.string-list".to_owned(),
        list.into(),
    )
    .await?;

    // Retrieve preferences
    let missing =
        CachedPreferences::get(account.address(), "mock.non-existent")
            .await?;
    assert!(matches!(missing, None));

    let boolean =
        CachedPreferences::get(account.address(), "mock.bool").await?;
    assert!(matches!(boolean, Some(Preference::Bool(_))));

    let int = CachedPreferences::get(account.address(), "mock.int").await?;
    assert!(matches!(int, Some(Preference::Int(_))));

    let double =
        CachedPreferences::get(account.address(), "mock.double").await?;
    assert!(matches!(double, Some(Preference::Double(_))));

    let string =
        CachedPreferences::get(account.address(), "mock.string").await?;
    assert!(matches!(string, Some(Preference::String(_))));

    let string_list =
        CachedPreferences::get(account.address(), "mock.string-list").await?;
    assert!(matches!(string_list, Some(Preference::StringList(_))));

    // Remove preferences
    let removed =
        CachedPreferences::remove(account.address(), "mock.bool").await?;
    assert!(matches!(removed, Some(Preference::Bool(true))));

    // Clear preferences
    CachedPreferences::clear(account.address()).await?;
    let prefs = CachedPreferences::load(account.address()).await;
    let items = prefs.iter().collect::<Vec<_>>();
    assert!(items.is_empty());

    account.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
