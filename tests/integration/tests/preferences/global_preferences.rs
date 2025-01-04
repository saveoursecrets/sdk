use crate::{
    assert_preferences,
    test_utils::{setup, teardown},
};
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

    assert_preferences(&mut prefs).await?;

    teardown(TEST_ID).await;

    Ok(())
}
