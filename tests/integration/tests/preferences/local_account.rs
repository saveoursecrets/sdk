use crate::{
    assert_preferences,
    test_utils::{setup, teardown},
};
use anyhow::Result;
use sos_account::{Account, LocalAccount};
use sos_net::extras::preferences::*;
use sos_sdk::prelude::*;

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

    let preferences = CachedPreferences::new(Some(data_dir.clone()))?;
    preferences.load_account_preferences(&identities).await?;

    let prefs = preferences.account_preferences(account.address()).await;
    assert!(prefs.is_some());
    let prefs = prefs.unwrap();
    let mut prefs = prefs.lock().await;

    assert_preferences(&mut prefs).await?;

    account.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
