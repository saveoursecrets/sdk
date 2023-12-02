use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::{
    events::Patch,
    sdk::{
        account::{LocalAccount, UserPaths},
        commit::CommitHash,
        events::{AccountEvent, AccountEventLog, FolderEventLog, WriteEvent},
        passwd::diceware::generate_passphrase,
    },
};

use super::last_log_event;

const TEST_ID: &str = "folder_events";

/// Tests events saved to a folder event log.
#[tokio::test]
async fn integration_events_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    UserPaths::scaffold(Some(data_dir.clone())).await?;
    UserPaths::new_global(data_dir.clone());

    let (mut account, new_account) = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let default_folder = new_account.default_folder();
    account.sign_in(password.clone()).await?;
    account.open_folder(&default_folder).await?;

    let folder_events = account
        .paths()
        .event_log_path(default_folder.id().to_string());

    // Just has the create vault event to begin with
    let mut event_log = FolderEventLog::new_folder(&folder_events).await?;
    let event = last_log_event(&mut event_log, None).await?;
    assert!(matches!(event, Some(WriteEvent::CreateVault(_))));

    // Create secret event
    let commit = event_log.last_commit().await?;
    let (meta, secret) = mock::note("note", TEST_ID);
    let (id, _, _, _) = account
        .create_secret(meta, secret, Default::default())
        .await?;
    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(WriteEvent::CreateSecret(_, _))));

    // Update secret event
    let commit = event_log.last_commit().await?;
    let (meta, secret) = mock::note("note_edited", TEST_ID);
    let (_, _, _, _) = account
        .update_secret(
            &id,
            meta.clone(),
            Some(secret),
            Default::default(),
            None,
        )
        .await?;
    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(WriteEvent::UpdateSecret(_, _))));

    // Delete secret event
    let commit = event_log.last_commit().await?;
    account.delete_secret(&id, Default::default()).await?;
    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(WriteEvent::DeleteSecret(_))));

    // Rename the folder
    let commit = event_log.last_commit().await?;
    account
        .rename_folder(&default_folder, "new_name".to_string())
        .await?;
    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(WriteEvent::SetVaultName(_))));

    teardown(TEST_ID).await;

    Ok(())
}
