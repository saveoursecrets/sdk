use anyhow::Result;
use sos_backend::Preferences;
use sos_core::Paths;
use sos_preferences::PreferenceManager;
use sos_test_utils::make_client_backend;
use sos_test_utils::{assert::assert_preferences, setup, teardown};

/// Tests the global preferences for all accounts.
#[tokio::test]
async fn preferences_global() -> Result<()> {
    const TEST_ID: &str = "preferences_global";
    //sos_test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_client(&data_dir);
    let target = make_client_backend(&paths).await?;

    let mut preferences = Preferences::new(target);
    preferences.load_global_preferences().await?;

    let prefs = preferences.global_preferences();
    let mut prefs = prefs.lock().await;

    assert_preferences(&mut prefs).await?;

    teardown(TEST_ID).await;

    Ok(())
}
