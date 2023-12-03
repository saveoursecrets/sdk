use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::{
    events::Patch,
    sdk::{
        account::{AccessOptions, LocalAccount, UserPaths},
        events::{FileEvent, FileEventLog},
        passwd::diceware::generate_passphrase,
        vault::secret::{IdentityKind, SecretId, SecretRow, SecretType},
        vfs,
    },
};

const TEST_ID: &str = "events_file";

/// Tests the various file events are being logged.
#[tokio::test]
async fn integration_events_file() -> Result<()> {
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

    // Create a folder so we can move the secret
    let folder_name = "folder_name";
    let (folder, _, _, _) =
        account.create_folder(folder_name.to_string()).await?;

    // Create an external file secret
    let (meta, secret, file_path) = mock::file_text_secret()?;
    let (id, _, _, _) = account
        .create_secret(meta, secret, Default::default())
        .await?;

    // Move the secret to move the associated file
    let (id, _) = account
        .move_secret(&id, &default_folder, &folder, Default::default())
        .await?;

    // Read secret so we can update the data with a file attachment
    let (mut data, _) =
        account.read_secret(&id, Some(folder.clone())).await?;

    // Add a file attachment
    let (meta, secret, _) = mock::file_text_secret()?;
    let attachment_id = SecretId::new_v4();
    let attachment = SecretRow::new(attachment_id, meta, secret);
    data.secret_mut().add_field(attachment);

    account
        .update_secret(
            &id,
            data.meta().clone(),
            Some(data.secret().clone()),
            AccessOptions {
                folder: Some(folder.clone()),
                file_progress: None,
            },
            None,
        )
        .await?;

    // Delete the secret should remove the file secret
    // and the file attachment (two delete events)
    account
        .delete_secret(
            &id,
            AccessOptions {
                folder: Some(folder.clone()),
                ..Default::default()
            },
        )
        .await?;

    // Store the file events log so we can delete and re-create
    let file_events = account.paths().file_events();

    let mut event_log = FileEventLog::new_file(&file_events).await?;
    let records = event_log.patch_until(None).await?;
    let patch: Patch = records.into();
    let events = patch.into_events::<FileEvent>().await?;
    assert_eq!(5, events.len());

    // Initial file secret creation
    assert!(matches!(
        events.get(0),
        Some(FileEvent::CreateFile(_, _, _))
    ));

    // Moving event
    assert!(matches!(events.get(1), Some(FileEvent::MoveFile { .. })));

    // Adding the file attachment triggered another create
    assert!(matches!(
        events.get(2),
        Some(FileEvent::CreateFile(_, _, _))
    ));

    // Both files were deleted
    assert!(matches!(
        events.get(3),
        Some(FileEvent::DeleteFile(_, _, _))
    ));
    assert!(matches!(
        events.get(4),
        Some(FileEvent::DeleteFile(_, _, _))
    ));

    teardown(TEST_ID).await;

    Ok(())
}
