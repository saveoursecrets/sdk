use anyhow::Result;
use sos_backend::Preferences;
use sos_preferences::PreferenceManager;
use sos_test_utils::{assert::assert_preferences, mock::memory_database};
use tempfile::tempdir_in;

#[tokio::test]
async fn fs_global_preferences() -> Result<()> {
    let temp = tempdir_in("target")?;
    let prefs = Preferences::new_fs_directory(Some(temp.path().to_owned()))?;
    let globals = prefs.global_preferences();
    let mut prefs = globals.lock().await;
    assert_preferences(&mut *prefs).await?;
    Ok(())
}

#[tokio::test]
async fn db_global_preferences() -> Result<()> {
    let client = memory_database().await?;
    let prefs = Preferences::new_db(client);
    let globals = prefs.global_preferences();
    let mut prefs = globals.lock().await;
    assert_preferences(&mut *prefs).await?;
    Ok(())
}
