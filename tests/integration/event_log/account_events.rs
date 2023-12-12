use super::last_log_event;
use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

const TEST_ID: &str = "events_account";

/// Tests that basic account events are being logged.
#[tokio::test]
async fn integration_events_account() -> Result<()> {
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

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    let account_events = account.paths().account_events();
    let mut event_log = AccountEventLog::new_account(&account_events).await?;
    let patch = event_log.diff(None).await?;
    let events: Vec<AccountEvent> = patch.into();
    assert_eq!(1, events.len());

    // Create a folder
    let commit = event_log.tree().last_commit();
    let folder_name = "folder_name";
    let (folder, _, _) =
        account.create_folder(folder_name.to_string()).await?;

    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(AccountEvent::CreateFolder(_))));

    // Now delete the folder
    let commit = event_log.tree().last_commit();
    account.delete_folder(&folder).await?;

    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(AccountEvent::DeleteFolder(_))));

    teardown(TEST_ID).await;

    Ok(())
}
