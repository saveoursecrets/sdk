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

    let mock_signer = SingleParty::new_random();
    let address = mock_signer.address()?;
    let identity = PublicIdentity::new("mock-user".to_owned(), address);

    // Ensure paths exist
    Paths::scaffold(Some(data_dir.clone())).await?;
    let paths = Paths::new(data_dir.clone(), address.to_string());
    paths.ensure().await?;

    // Prepare the preferences
    let accounts = vec![identity];
    CachedPreferences::initialize(accounts.as_slice(), Some(data_dir))
        .await?;

    let prefs = CachedPreferences::account_preferences(&address).await;
    assert!(prefs.is_some());

    let prefs = prefs.unwrap();
    let mut prefs = prefs.lock().await;

    // Non-existent key
    assert!(prefs.get_unchecked("no-pref").is_none());

    // Insertion and type-checking
    prefs
        .insert("int-1".to_owned(), Preference::Int(-12))
        .await?;
    assert!(prefs.get_int("int-1")?.is_some());
    assert!(prefs.get_bool("int-1").is_err());

    prefs
        .insert("double-1".to_owned(), Preference::Double(3.14))
        .await?;
    assert!(prefs.get_double("double-1")?.is_some());
    assert!(prefs.get_int("double-1").is_err());

    prefs
        .insert("bool-1".to_owned(), Preference::Bool(true))
        .await?;
    assert!(prefs.get_bool("bool-1")?.is_some());
    assert!(prefs.get_double("bool-1").is_err());

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
    assert!(prefs.get_int("int-1")?.is_none());

    // Clear all preferences
    prefs.clear().await?;

    teardown(TEST_ID).await;

    Ok(())
}
