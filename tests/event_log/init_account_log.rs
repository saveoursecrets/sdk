use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests lazy initialization of the account events log.
#[tokio::test]
async fn event_log_init_account_log() -> Result<()> {
    const TEST_ID: &str = "event_log_init_account_log";
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

    // Sign in should lazily initialize the account event log
    // from the folders on disc
    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    let account_events = account.paths().account_events();
    let event_log = AccountEventLog::new_account(&account_events).await?;
    let patch = event_log.diff(None).await?;
    let events: Vec<AccountEvent> = patch.into();
    assert_eq!(1, events.len());

    assert!(matches!(
        events.get(0),
        Some(AccountEvent::CreateFolder(_, _))
    ));

    teardown(TEST_ID).await;

    Ok(())
}
