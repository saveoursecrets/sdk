use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_backend::Preferences;
use sos_core::AccountId;
use sos_preferences::{Preference, PreferenceManager};
use sos_sdk::prelude::*;
use sos_test_utils::make_client_backend;

/// Tests the cached preferences without any accounts or authentication.
#[tokio::test]
async fn preferences_no_account() -> Result<()> {
    const TEST_ID: &str = "preferences_no_account";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_id = AccountId::random();
    let identity = PublicIdentity::new(account_id, "mock-user".to_owned());

    // Ensure paths exist
    Paths::scaffold(&data_dir).await?;
    let paths = Paths::new_client(&data_dir).with_account_id(&account_id);
    paths.ensure().await?;

    let target = make_client_backend(&paths).await?;

    // Prepare the preferences
    let accounts = vec![identity];
    let preferences = Preferences::new(target);
    preferences
        .load_account_preferences(accounts.as_slice())
        .await?;

    let prefs = preferences.account_preferences(&account_id).await;
    assert!(prefs.is_some());

    let prefs = prefs.unwrap();
    let mut prefs = prefs.lock().await;

    // Non-existent key
    assert!(prefs.get_unchecked("no-pref").is_none());

    // Insertion and type-checking
    prefs
        .insert("int-1".to_owned(), Preference::Number(-12.0))
        .await?;
    assert!(prefs.get_number("int-1")?.is_some());
    assert!(prefs.get_bool("int-1").is_err());

    prefs
        .insert("double-1".to_owned(), Preference::Number(3.14))
        .await?;
    assert!(prefs.get_number("double-1")?.is_some());
    assert!(prefs.get_bool("double-1").is_err());

    prefs
        .insert("bool-1".to_owned(), Preference::Bool(true))
        .await?;
    assert!(prefs.get_bool("bool-1")?.is_some());
    assert!(prefs.get_number("bool-1").is_err());

    prefs
        .insert("string-1".to_owned(), Preference::String("foo".to_owned()))
        .await?;
    assert!(prefs.get_string("string-1")?.is_some());
    assert!(prefs.get_bool("string-1").is_err());

    prefs
        .insert(
            "string-list-1".to_owned(),
            Preference::StringList(vec!["foo".to_owned(), "bar".to_owned()]),
        )
        .await?;
    assert!(prefs.get_string_list("string-list-1")?.is_some());
    assert!(prefs.get_string("string-list-1").is_err());

    // Removal
    assert!(prefs.remove("int-1").await?.is_some());
    assert!(prefs.get_number("int-1")?.is_none());

    // Clear all preferences
    prefs.clear().await?;

    teardown(TEST_ID).await;

    Ok(())
}
