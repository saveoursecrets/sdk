use anyhow::Result;
use sos_backend::Preferences;
use sos_core::{AccountId, Paths};
use sos_preferences::PreferenceManager;
use sos_test_utils::{
    assert::assert_preferences,
    mock::{insert_database_account, memory_database},
};
use tempfile::tempdir_in;

#[tokio::test]
async fn fs_account_preferences() -> Result<()> {
    let temp = tempdir_in("target")?;
    let account_id = AccountId::random();

    let paths = Paths::new_client(temp.path()).with_account_id(&account_id);
    paths.ensure().await?;
    let prefs = Preferences::new_fs(paths);
    prefs.new_account(&account_id).await?;

    let prefs = prefs.account_preferences(&account_id).await.unwrap();
    let mut prefs = prefs.lock().await;
    assert_preferences(&mut *prefs).await?;
    Ok(())
}

#[tokio::test]
async fn db_account_preferences() -> Result<()> {
    let mut client = memory_database().await?;
    let (account_id, _) = insert_database_account(&mut client).await?;
    let prefs = Preferences::new_db(client);
    prefs.new_account(&account_id).await?;
    let prefs = prefs.account_preferences(&account_id).await.unwrap();
    let mut prefs = prefs.lock().await;
    assert_preferences(&mut *prefs).await?;
    Ok(())
}
