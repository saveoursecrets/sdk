use super::last_log_event;
use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::{
    events::Patch,
    sdk::{
        account::{AccessOptions, LocalAccount, UserPaths},
        events::{AccountEvent, AccountEventLog},
        passwd::diceware::generate_passphrase,
        vault::secret::{IdentityKind, SecretId, SecretRow, SecretType},
        vfs,
    },
};

const TEST_ID: &str = "account_events";

/// Tests that basic account events are being logged.
#[tokio::test]
async fn integration_events_account() -> Result<()> {
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

    let account_events = account.paths().account_events();
    let mut event_log = AccountEventLog::new_account(&account_events).await?;
    let records = event_log.patch_until(None).await?;
    let patch: Patch = records.into();
    let events = patch.into_events::<AccountEvent>().await?;
    assert_eq!(1, events.len());

    // Create a folder
    let commit = event_log.last_commit().await?;
    let folder_name = "folder_name";
    let (folder, _, _, _) =
        account.create_folder(folder_name.to_string()).await?;

    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(AccountEvent::CreateFolder(_, _))));

    // Now delete the folder
    let commit = event_log.last_commit().await?;
    account.delete_folder(&folder).await?;

    let event = last_log_event(&mut event_log, commit.as_ref()).await?;
    assert!(matches!(event, Some(AccountEvent::DeleteFolder(_))));

    teardown(TEST_ID).await;

    Ok(())
}
