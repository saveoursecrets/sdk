use anyhow::Result;

use crate::test_utils::{mock, setup, teardown};

use sos_net::sdk::prelude::*;

use super::last_log_event;

const TEST_ID: &str = "events_change_password";

/// Tests the account events after changing the encryption
/// password of a folder.
#[tokio::test]
async fn integration_events_change_password() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let (mut account, new_account) = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let default_folder = new_account.default_folder();
    let key: AccessKey = password.into();
    account.sign_in(&key).await?;
    account.open_folder(&default_folder).await?;

    // Create some secrets
    let docs = vec![
        mock::note("note", "secret"),
        mock::card("card", TEST_ID, "123"),
        mock::bank("bank", TEST_ID, "12-34-56"),
    ];
    let results = account.insert_secrets(docs).await?;
    let mut ids: Vec<_> = results.into_iter().map(|r| r.0).collect();

    let (new_password, _) = generate_passphrase()?;
    let new_key: AccessKey = new_password.into();

    let account_events = account.paths().account_events();
    let mut event_log = AccountEventLog::new_account(&account_events).await?;
    let commit = event_log.last_commit().await?;

    // Change the folder password
    account
        .change_folder_password(&default_folder, new_key.clone())
        .await?;

    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(AccountEvent::ChangeFolderPassword(_))));

    // Should be able to continue reading data
    // from the currently open folder which had
    // it's password changed.
    let note_id = ids.remove(0);
    let (data, _) = account.read_secret(&note_id, None).await?;
    assert_eq!("note", data.meta().label());

    teardown(TEST_ID).await;

    Ok(())
}
