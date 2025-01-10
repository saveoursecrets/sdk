use super::last_log_event;
use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_account::{Account, LocalAccount};
use sos_backend::AccountEventLog;
use sos_sdk::prelude::*;

/// Tests the account events after changing the encryption
/// password of a folder.
#[tokio::test]
async fn event_log_change_password() -> Result<()> {
    const TEST_ID: &str = "event_log_change_password";
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
    let default_folder = account.default_folder().await.unwrap();

    // Create some secrets
    let docs = vec![
        mock::note("note", "secret"),
        mock::card("card", TEST_ID, "123"),
        mock::bank("bank", TEST_ID, "12-34-56"),
    ];
    let bulk = account.insert_secrets(docs).await?;
    let mut ids: Vec<_> = bulk.results.into_iter().map(|r| r.id).collect();

    let (new_password, _) = generate_passphrase()?;
    let new_key: AccessKey = new_password.into();

    let account_events = account.paths().account_events();
    let mut event_log =
        AccountEventLog::new_fs_account(&account_events).await?;
    let commit = event_log.tree().last_commit();

    // Change the folder password
    account
        .change_folder_password(&default_folder, new_key.clone())
        .await?;

    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(
        event,
        Some(AccountEvent::ChangeFolderPassword(_, _))
    ));

    // Should be able to continue reading data
    // from the currently open folder which had
    // it's password changed.
    let note_id = ids.remove(0);
    let (data, _) = account.read_secret(&note_id, None).await?;
    assert_eq!("note", data.meta().label());

    teardown(TEST_ID).await;

    Ok(())
}
