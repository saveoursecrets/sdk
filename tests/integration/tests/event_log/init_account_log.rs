use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_account::{Account, LocalAccount};
use sos_backend::AccountEventLog;
use sos_core::{
    crypto::AccessKey,
    events::{AccountEvent, EventLog},
    Paths,
};
use sos_password::diceware::generate_passphrase;
use sos_test_utils::make_client_backend;

/// Tests lazy initialization of the account events log.
#[tokio::test]
async fn event_log_init_account_log() -> Result<()> {
    const TEST_ID: &str = "event_log_init_account_log";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_global(&data_dir);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        make_client_backend(&paths),
        Some(data_dir.clone()),
    )
    .await?;

    // Sign in should lazily initialize the account event log
    // from the folders on disc
    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    let account_events = account.paths().account_events();
    let event_log = AccountEventLog::new_fs_account(&account_events).await?;
    let patch = event_log.diff_events(None).await?;
    let events = patch.into_events().await?;
    assert_eq!(1, events.len());

    assert!(matches!(
        events.get(0),
        Some(AccountEvent::CreateFolder(_, _))
    ));

    teardown(TEST_ID).await;

    Ok(())
}
