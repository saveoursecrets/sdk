use super::last_log_event;
use sos_test_utils::{mock, setup, teardown};
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

/// Tests the update folder event when importing a folder
/// that overwrites an existing folder.
#[tokio::test]
async fn event_log_import_folder() -> Result<()> {
    const TEST_ID: &str = "event_log_import_folder";
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
        target.clone(),
    )
    .await?;

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;
    let default_folder = account.default_folder().await.unwrap();

    // Create some data
    let docs = vec![
        mock::note("note", "secret"),
        mock::card("card", TEST_ID, "123"),
        mock::bank("bank", TEST_ID, "12-34-56"),
    ];
    account.insert_secrets(docs).await?;

    // Export the folder to a buffer
    let (vault_password, _) = generate_passphrase()?;
    let vault_key: AccessKey = vault_password.into();
    let buffer = account
        .export_folder_buffer(default_folder.id(), vault_key.clone(), false)
        .await?;

    let mut event_log =
        AccountEventLog::new_account(target, account.account_id()).await?;

    // Import overwriting the existing data
    let commit = event_log.tree().last_commit();
    account
        .import_folder_buffer(&buffer, vault_key.clone(), true)
        .await?;

    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(AccountEvent::UpdateFolder(_, _))));

    teardown(TEST_ID).await;

    Ok(())
}
