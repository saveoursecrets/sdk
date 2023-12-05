use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::{events::Patch, sdk::prelude::*};

use super::last_log_event;

const TEST_ID: &str = "events_import_folder";

/// Tests the update folder event when importing a folder
/// that overwrites an existing folder.
#[tokio::test]
async fn integration_events_import_folder() -> Result<()> {
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

    // Create some data
    let docs = vec![
        mock::note("note", "secret"),
        mock::card("card", TEST_ID, "123"),
        mock::bank("bank", TEST_ID, "12-34-56"),
    ];
    let results = account.insert_secrets(docs).await?;
    let ids: Vec<_> = results.into_iter().map(|r| r.0).collect();

    // Export the folder to a buffer
    let (vault_password, _) = generate_passphrase()?;
    let vault_key: AccessKey = vault_password.into();
    let buffer = account
        .export_folder_buffer(&default_folder, vault_key.clone(), false)
        .await?;

    let account_events = account.paths().account_events();
    let mut event_log = AccountEventLog::new_account(&account_events).await?;

    // Import overwriting the existing data
    let commit = event_log.last_commit().await?;
    account
        .import_folder_buffer(&buffer, vault_key.clone(), true)
        .await?;

    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    println!("{:#?}", event);
    assert!(matches!(event, Some(AccountEvent::UpdateFolder(_, _))));

    teardown(TEST_ID).await;

    Ok(())
}
