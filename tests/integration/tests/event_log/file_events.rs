use super::all_events;
use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_account::{
    Account, FolderCreate, LocalAccount, SecretChange, SecretMove,
};
use sos_backend::FileEventLog;
use sos_client_storage::{AccessOptions, NewFolderOptions};
use sos_sdk::prelude::*;

/// Tests the various file events are being logged.
#[tokio::test]
async fn event_log_file() -> Result<()> {
    const TEST_ID: &str = "event_log_file";

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

    // Create a folder so we can move the secret
    let folder_name = "folder_name";
    let FolderCreate { folder, .. } = account
        .create_folder(NewFolderOptions::new(folder_name.to_string()))
        .await?;

    // Create an external file secret
    let (meta, secret, _file_path) = mock::file_text_secret()?;
    let SecretChange { id, .. } = account
        .create_secret(meta, secret, Default::default())
        .await?;

    // Move the secret to move the associated file
    let SecretMove { id, .. } = account
        .move_secret(&id, &default_folder, &folder, Default::default())
        .await?;

    // Read secret so we can update the data with a file attachment
    let (mut data, _) = account.read_secret(&id, Some(folder.id())).await?;

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
                folder: Some(*folder.id()),
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
                folder: Some(*folder.id()),
                ..Default::default()
            },
        )
        .await?;

    // Store the file events log so we can delete and re-create
    let file_events = account.paths().file_events();

    let event_log = FileEventLog::new_fs_file(&file_events).await?;
    let patch = event_log.diff_events(None).await?;
    let events: Vec<FileEvent> = patch.into_events().await?;
    assert_eq!(5, events.len());

    // Initial file secret creation
    assert!(matches!(events.get(0), Some(FileEvent::CreateFile(_, _))));

    // Moving event
    assert!(matches!(events.get(1), Some(FileEvent::MoveFile { .. })));

    // Adding the file attachment triggered another create
    assert!(matches!(events.get(2), Some(FileEvent::CreateFile(_, _))));

    // Both files were deleted
    assert!(matches!(events.get(3), Some(FileEvent::DeleteFile(_, _))));
    assert!(matches!(events.get(4), Some(FileEvent::DeleteFile(_, _))));

    teardown(TEST_ID).await;

    Ok(())
}

/// Tests that delete file events are logged when a folder
/// is deleted.
#[tokio::test]
async fn event_log_file_folder_delete() -> Result<()> {
    const TEST_ID: &str = "event_log_file_folder_delete";

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

    // Create some external file secrets
    let (meta, secret, _) = mock::file_text_secret()?;
    account
        .create_secret(meta, secret, Default::default())
        .await?;
    let (meta, secret, _) = mock::file_image_secret()?;
    account
        .create_secret(meta, secret, Default::default())
        .await?;

    // Delete the folder
    account.delete_folder(default_folder.id()).await?;

    // Store the file events log so we can delete and re-create
    let file_events = account.paths().file_events();

    let mut event_log = FileEventLog::new_fs_file(&file_events).await?;
    let events = all_events(&mut event_log).await?;
    assert_eq!(4, events.len());
    assert!(matches!(events.get(0), Some(FileEvent::CreateFile(_, _))));
    assert!(matches!(events.get(1), Some(FileEvent::CreateFile(_, _))));
    // Both files were deleted
    assert!(matches!(events.get(2), Some(FileEvent::DeleteFile(_, _))));
    assert!(matches!(events.get(3), Some(FileEvent::DeleteFile(_, _))));

    teardown(TEST_ID).await;

    Ok(())
}
