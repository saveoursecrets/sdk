use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::extras::preferences::*;

/// Tests the global preferences for all accounts.
#[tokio::test]
async fn preferences_global() -> Result<()> {
    const TEST_ID: &str = "preferences_global";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let mut preferences = CachedPreferences::new(Some(data_dir.clone()))?;
    preferences.load_global_preferences().await?;

    let prefs = preferences.global_preferences();
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

    teardown(TEST_ID).await;

    Ok(())
}
