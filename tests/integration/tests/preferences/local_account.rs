use anyhow::Result;
use sos_account::{Account, LocalAccount};
use sos_backend::Preferences;
use sos_core::Paths;
use sos_preferences::PreferenceManager;
use sos_sdk::prelude::*;
use sos_test_utils::{
    assert::assert_preferences, make_client_backend, setup, teardown,
};

/// Tests the preferences in the context of a local account.
#[tokio::test]
async fn preferences_local_account() -> Result<()> {
    const TEST_ID: &str = "preferences_local_account";
    //sos_test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_client(&data_dir);
    let target = make_client_backend(&paths).await?;

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        make_client_backend(&paths).await?,
    )
    .await?;

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    let identity = account.public_identity().await?.clone();
    let identities = vec![identity];

    let preferences = Preferences::new(target);
    preferences.load_account_preferences(&identities).await?;

    let prefs = preferences.account_preferences(account.account_id()).await;
    assert!(prefs.is_some());
    let prefs = prefs.unwrap();
    let mut prefs = prefs.lock().await;

    assert_preferences(&mut prefs).await?;

    account.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
