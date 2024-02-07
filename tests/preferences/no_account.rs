use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::sdk::{
    prelude::*,
    signer::{ecdsa::SingleParty, Signer},
};

/// Tests the cached preferences without any accounts or authentication.
#[tokio::test]
async fn preferences_no_account() -> Result<()> {
    const TEST_ID: &str = "preferences_no_account";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let mock_signer_1 = SingleParty::new_random();
    let address_1 = mock_signer_1.address()?;
    let identity_1 = PublicIdentity::new("mock-user-1".to_owned(), address_1);

    let mock_signer_2 = SingleParty::new_random();
    let address_2 = mock_signer_2.address()?;
    let identity_2 = PublicIdentity::new("mock-user-2".to_owned(), address_2);

    // Ensure paths exist
    Paths::scaffold(Some(data_dir.clone())).await?;
    let paths = Paths::new(data_dir.clone(), address_1.to_string());
    paths.ensure().await?;
    let paths = Paths::new(data_dir.clone(), address_2.to_string());
    paths.ensure().await?;

    // Prepare the preferences
    let accounts = vec![identity_1, identity_2];
    CachedPreferences::initialize(accounts.as_slice(), Some(data_dir))
        .await?;

    let prefs_1 = CachedPreferences::account_preferences(&address_1).await;
    assert!(prefs_1.is_some());

    let prefs_2 = CachedPreferences::account_preferences(&address_2).await;
    assert!(prefs_2.is_some());

    let prefs_1 = prefs_1.unwrap();
    let mut prefs_1 = prefs_1.lock().await;

    // Non-existent key
    assert!(prefs_1.get_unchecked("no-pref").is_none());

    // Insertion and type-checking
    prefs_1
        .insert("int-1".to_owned(), Preference::Int(-12))
        .await?;
    assert!(prefs_1.get_int("int-1")?.is_some());
    assert!(prefs_1.get_bool("int-1").is_err());

    prefs_1
        .insert("double-1".to_owned(), Preference::Double(3.14))
        .await?;
    assert!(prefs_1.get_double("double-1")?.is_some());
    assert!(prefs_1.get_int("double-1").is_err());

    prefs_1
        .insert("bool-1".to_owned(), Preference::Bool(true))
        .await?;
    assert!(prefs_1.get_bool("bool-1")?.is_some());
    assert!(prefs_1.get_double("bool-1").is_err());

    prefs_1
        .insert("string-1".to_owned(), Preference::String("foo".to_owned()))
        .await?;
    assert!(prefs_1.get_string("string-1")?.is_some());
    assert!(prefs_1.get_bool("string-1").is_err());

    prefs_1
        .insert(
            "string-list-1".to_owned(),
            Preference::StringList(vec!["foo".to_owned(), "bar".to_owned()]),
        )
        .await?;
    assert!(prefs_1.get_string_list("string-list-1")?.is_some());
    assert!(prefs_1.get_string("string-list-1").is_err());

    // Removal
    assert!(prefs_1.remove("int-1").await?.is_some());
    assert!(prefs_1.get_int("int-1")?.is_none());

    // Clear all preferences
    prefs_1.clear().await?;

    teardown(TEST_ID).await;

    Ok(())
}
