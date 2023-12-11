use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::{events::Patch, sdk::prelude::*};

const TEST_ID: &str = "events_init_account_log";

/// Tests lazy initialization of the account events log.
#[tokio::test]
async fn integration_events_init_account_log() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    // Sign in should lazily initialize the account event log
    // from the folders on disc
    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    let account_events = account.paths().account_events();
    let event_log = AccountEventLog::new_account(&account_events).await?;
    let records = event_log.diff_records(None).await?;
    let patch: Patch = records.into();
    let events = patch.into_events::<AccountEvent>().await?;
    assert_eq!(1, events.len());

    assert!(matches!(events.get(0), Some(AccountEvent::CreateFolder(_))));

    teardown(TEST_ID).await;

    Ok(())
}
