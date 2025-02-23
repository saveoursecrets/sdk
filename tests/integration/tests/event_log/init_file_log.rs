use super::last_log_event;
use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_account::{Account, LocalAccount};
use sos_backend::FileEventLog;
use sos_core::{
    crypto::AccessKey,
    events::{EventLog, FileEvent},
    Paths,
};
use sos_password::diceware::generate_passphrase;
use sos_test_utils::make_client_backend;
use sos_vfs as vfs;

/// Tests lazy initialization of the file events log.
#[tokio::test]
async fn event_log_init_file_log() -> Result<()> {
    const TEST_ID: &str = "event_log_init_file_log";
    // crate::test_utils::init_tracing();

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

    let paths = account.paths();
    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    // Create an external file secret
    let (meta, secret, _file_path) = mock::file_text_secret()?;
    account
        .create_secret(meta, secret, Default::default())
        .await?;

    // Store the file events log so we can delete and re-create
    let event_log =
        FileEventLog::new_file(target.clone(), account.account_id()).await?;
    let patch = event_log.diff_events(None).await?;
    assert_eq!(1, patch.len());
    let events = patch.into_events().await?;
    assert!(matches!(events.get(0), Some(FileEvent::CreateFile(_, _))));

    // Sign out the account
    account.sign_out().await?;

    // Delete the file events stored on disc
    if !paths.is_using_db() {
        vfs::remove_file(paths.file_events()).await?;
    }

    // Sign in again to lazily create the file events
    // from the state on disc
    account.sign_in(&key).await?;

    // Check the event log was initialized from the files on disc
    let mut event_log =
        FileEventLog::new_file(target, account.account_id()).await?;
    let event = last_log_event(&mut event_log, None).await?;
    assert!(matches!(event, Some(FileEvent::CreateFile(_, _))));

    teardown(TEST_ID).await;

    Ok(())
}
