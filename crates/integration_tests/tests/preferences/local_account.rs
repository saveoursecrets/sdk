use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::{extras::preferences::*, sdk::prelude::*};

/// Tests the preferences in the context of a local account.
#[tokio::test]
async fn preferences_local_account() -> Result<()> {
    const TEST_ID: &str = "preferences_local_account";
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

    let prefs =
        CachedPreferences::account_preferences(account.address()).await;
    assert!(prefs.is_some());
    let prefs = prefs.unwrap();
    let mut prefs = prefs.lock().await;

    // Create preferences
    prefs.insert("mock.bool".to_owned(), true.into()).await?;

    prefs
        .insert("mock.int".to_owned(), (-15 as i64).into())
        .await?;

    prefs
        .insert("mock.double".to_owned(), (3.14 as f64).into())
        .await?;

    prefs
        .insert("mock.string".to_owned(), "message".to_owned().into())
        .await?;
    let list = vec!["item-1".to_owned(), "item-2".to_owned()];
    prefs
        .insert("mock.string-list".to_owned(), list.into())
        .await?;

    // Retrieve preferences
    let missing = prefs.get_unchecked("mock.non-existent");
    assert!(missing.is_none());

    let boolean = prefs.get_bool("mock.bool")?;
    assert!(matches!(boolean, Some(Preference::Bool(_))));

    let int = prefs.get_number("mock.int")?;
    assert!(matches!(int, Some(Preference::Number(_))));

    let double = prefs.get_number("mock.double")?;
    assert!(matches!(double, Some(Preference::Number(_))));

    let string = prefs.get_string("mock.string")?;
    assert!(matches!(string, Some(Preference::String(_))));

    let string_list = prefs.get_string_list("mock.string-list")?;
    assert!(matches!(string_list, Some(Preference::StringList(_))));

    // Remove preferences
    let removed = prefs.remove("mock.bool").await?;
    assert!(matches!(removed, Some(Preference::Bool(true))));

    // Clear preferences
    prefs.clear().await?;

    // Reload
    prefs.load().await?;
    let items = prefs.iter().collect::<Vec<_>>();
    assert!(items.is_empty());

    account.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
