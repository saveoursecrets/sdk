use super::last_log_event;
use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_account::{Account, FolderCreate, LocalAccount};
use sos_backend::AccountEventLog;
use sos_client_storage::NewFolderOptions;
use sos_core::{
    crypto::AccessKey,
    events::{AccountEvent, EventLog},
    Paths,
};
use sos_password::diceware::generate_passphrase;
use sos_test_utils::make_client_backend;

/// Tests that basic account events are being logged.
#[tokio::test]
async fn event_log_account() -> Result<()> {
    const TEST_ID: &str = "event_log_account";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_global(&data_dir);
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

    let mut event_log =
        AccountEventLog::new_account(*account.account_id(), target).await?;
    let patch = event_log.diff_events(None).await?;
    assert_eq!(1, patch.len());

    // Create a folder
    let commit = event_log.tree().last_commit();
    let folder_name = "folder_name";
    let FolderCreate { folder, .. } = account
        .create_folder(NewFolderOptions::new(folder_name.to_string()))
        .await?;

    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(AccountEvent::CreateFolder(_, _))));

    // Now delete the folder
    let commit = event_log.tree().last_commit();
    account.delete_folder(folder.id()).await?;

    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(AccountEvent::DeleteFolder(_))));

    teardown(TEST_ID).await;

    Ok(())
}
