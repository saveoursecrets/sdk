use anyhow::Result;
use sos_backend::{BackendTarget, Preferences};
use sos_core::Paths;
use sos_preferences::PreferenceManager;
use sos_test_utils::{assert::assert_preferences, mock::memory_database};
use tempfile::tempdir_in;

#[tokio::test]
async fn fs_global_preferences() -> Result<()> {
    let temp = tempdir_in("target")?;
    let paths = Paths::new_client(temp.path());
    let prefs = Preferences::new(BackendTarget::FileSystem(paths));
    let globals = prefs.global_preferences();
    let mut prefs = globals.lock().await;
    assert_preferences(&mut *prefs).await?;
    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn db_global_preferences() -> Result<()> {
    let temp = tempdir_in("target")?;
    let paths = Paths::new_client(temp.path());
    let client = memory_database().await?;
    let prefs = Preferences::new(BackendTarget::Database(paths, client));
    let globals = prefs.global_preferences();
    let mut prefs = globals.lock().await;
    assert_preferences(&mut *prefs).await?;
    temp.close()?;
    Ok(())
}
