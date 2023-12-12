use anyhow::Result;
use sos_net::sdk::{hex, prelude::*};
use std::{path::PathBuf, sync::Arc};

use crate::test_utils::{mock, setup, teardown};
use tokio::sync::{mpsc, Mutex};

const TEST_ID: &str = "external_files";

/// Tests for the external file logic for a local account.
#[tokio::test]
async fn integration_external_files() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;
    let summary = account.default_folder().await.unwrap();

    let operations: Arc<Mutex<Vec<FileProgress>>> =
        Arc::new(Mutex::new(Vec::new()));
    let (progress_tx, mut progress_rx) = mpsc::channel::<FileProgress>(32);

    let operations_log = Arc::clone(&operations);
    tokio::task::spawn(async move {
        while let Some(msg) = progress_rx.recv().await {
            let mut writer = operations_log.lock().await;
            writer.push(msg);
        }
    });

    let (id, secret_data, original_checksum) = assert_create_file_secret(
        &mut account,
        &summary,
        progress_tx.clone(),
    )
    .await?;

    pause().await;

    let mut progress: Vec<_> = {
        let mut writer = operations.lock().await;
        writer.drain(..).collect()
    };
    assert_eq!(1, progress.len());
    assert!(matches!(progress.remove(0), FileProgress::Write { .. }));

    let (new_id, _new_secret_data, updated_checksum) =
        assert_update_file_secret(
            &mut account,
            &summary,
            &id,
            &secret_data,
            &original_checksum,
            progress_tx.clone(),
        )
        .await?;

    pause().await;

    // Update reports Delete and Write progress events
    let mut progress: Vec<_> = {
        let mut writer = operations.lock().await;
        writer.drain(..).collect()
    };
    assert_eq!(2, progress.len());
    assert!(matches!(progress.remove(0), FileProgress::Delete { .. }));
    assert!(matches!(progress.remove(0), FileProgress::Write { .. }));

    let (destination, moved_id, _moved_secret_data, moved_checksum) =
        assert_move_file_secret(
            &mut account,
            &summary,
            &new_id,
            &updated_checksum,
            progress_tx.clone(),
        )
        .await?;

    pause().await;

    let mut progress: Vec<_> = {
        let mut writer = operations.lock().await;
        writer.drain(..).collect()
    };
    assert_eq!(1, progress.len());
    assert!(matches!(progress.remove(0), FileProgress::Move { .. }));

    assert_delete_file_secret(
        &mut account,
        &destination,
        &moved_id,
        &moved_checksum,
        progress_tx.clone(),
    )
    .await?;

    pause().await;

    let mut progress: Vec<_> = {
        let mut writer = operations.lock().await;
        writer.drain(..).collect()
    };
    assert_eq!(1, progress.len());
    assert!(matches!(progress.remove(0), FileProgress::Delete { .. }));

    let (destination, id, checksum) = assert_create_update_move_file_secret(
        &mut account,
        &summary,
        progress_tx.clone(),
    )
    .await?;

    pause().await;

    let mut progress: Vec<_> = {
        let mut writer = operations.lock().await;
        writer.drain(..).collect()
    };
    assert_eq!(4, progress.len());
    assert!(matches!(progress.remove(0), FileProgress::Write { .. }));
    assert!(matches!(progress.remove(0), FileProgress::Delete { .. }));
    assert!(matches!(progress.remove(0), FileProgress::Write { .. }));
    assert!(matches!(progress.remove(0), FileProgress::Move { .. }));

    // NOTE: deleting a folder does not dispatch FileProgress events
    assert_delete_folder_file_secrets(
        &mut account,
        &destination,
        &id,
        &checksum,
    )
    .await?;

    assert_attach_file_secret(&mut account, &summary, progress_tx.clone())
        .await?;

    pause().await;

    let mut progress: Vec<_> = {
        let mut writer = operations.lock().await;
        writer.drain(..).collect()
    };
    assert_eq!(8, progress.len());
    assert!(matches!(progress.remove(0), FileProgress::Write { .. }));
    assert!(matches!(progress.remove(0), FileProgress::Write { .. }));
    assert!(matches!(progress.remove(0), FileProgress::Delete { .. }));
    assert!(matches!(progress.remove(0), FileProgress::Write { .. }));
    assert!(matches!(progress.remove(0), FileProgress::Write { .. }));
    assert!(matches!(progress.remove(0), FileProgress::Delete { .. }));
    assert!(matches!(progress.remove(0), FileProgress::Delete { .. }));
    assert!(matches!(progress.remove(0), FileProgress::Delete { .. }));

    teardown(TEST_ID).await;

    Ok(())
}

async fn create_file_secret(
    account: &mut LocalAccount,
    default_folder: &Summary,
    progress_tx: mpsc::Sender<FileProgress>,
) -> Result<(SecretId, SecretRow, PathBuf)> {
    let (meta, secret, file_path) = mock::file_image_secret()?;

    // Create the file secret in the default folder
    let options = AccessOptions {
        folder: Some(default_folder.clone()),
        file_progress: Some(progress_tx),
    };
    let (id, _, _, _) = account.create_secret(meta, secret, options).await?;
    let (secret_data, _) = account
        .read_secret(&id, Some(default_folder.clone()))
        .await?;

    Ok((id, secret_data, file_path))
}

async fn update_file_secret(
    account: &mut LocalAccount,
    default_folder: &Summary,
    secret_data: &SecretRow,
    destination: Option<&Summary>,
    progress_tx: mpsc::Sender<FileProgress>,
) -> Result<SecretRow> {
    let id = *secret_data.id();

    let mut new_meta = secret_data.meta().clone();
    new_meta.set_label("Text file".to_string());

    let (new_id, _, _, _) = account
        .update_file(
            &id,
            new_meta,
            "tests/fixtures/test-file.txt",
            AccessOptions {
                folder: None,
                file_progress: Some(progress_tx),
            },
            destination,
        )
        .await?;

    let folder = destination
        .cloned()
        .unwrap_or_else(|| default_folder.clone());
    let (new_secret_data, _) =
        account.read_secret(&new_id, Some(folder)).await?;

    Ok(new_secret_data)
}

async fn assert_create_file_secret(
    account: &mut LocalAccount,
    default_folder: &Summary,
    progress_tx: mpsc::Sender<FileProgress>,
) -> Result<(SecretId, SecretRow, [u8; 32])> {
    let (id, secret_data, file_path) =
        create_file_secret(account, default_folder, progress_tx).await?;

    let checksum = if let Secret::File {
        content:
            FileContent::External {
                mime,
                size,
                checksum,
                path,
                ..
            },
        ..
    } = secret_data.secret()
    {
        assert!(path.is_none());
        assert!(*size > 0);
        assert_ne!(&ZERO, checksum);
        assert_eq!("image/heic", mime);

        let file_name = hex::encode(checksum);
        let expected_file_path = account.paths().file_location(
            default_folder.id(),
            &id,
            &file_name,
        );

        assert!(vfs::try_exists(&expected_file_path).await?);

        let source_buffer = vfs::read(file_path).await?;
        let encrypted_buffer = vfs::read(&expected_file_path).await?;

        assert_ne!(source_buffer, encrypted_buffer);

        *checksum
    } else {
        panic!("expecting file secret variant");
    };

    Ok((id, secret_data, checksum))
}

async fn assert_update_file_secret(
    account: &mut LocalAccount,
    default_folder: &Summary,
    id: &SecretId,
    secret_data: &SecretRow,
    original_checksum: &[u8; 32],
    progress_tx: mpsc::Sender<FileProgress>,
) -> Result<(SecretId, SecretRow, [u8; 32])> {
    let new_secret_data = update_file_secret(
        account,
        default_folder,
        secret_data,
        None,
        progress_tx,
    )
    .await?;

    let checksum = if let Secret::File {
        content:
            FileContent::External {
                mime,
                size,
                checksum,
                path,
                ..
            },
        ..
    } = new_secret_data.secret()
    {
        assert!(path.is_none());
        assert!(*size > 0);
        assert_ne!(&ZERO, checksum);
        assert_eq!("text/plain", mime);

        let file_name = hex::encode(checksum);
        let expected_file_path = account.paths().file_location(
            default_folder.id(),
            id,
            &file_name,
        );
        assert!(vfs::try_exists(&expected_file_path).await?);

        let old_file_name = hex::encode(original_checksum);
        let old_file_path = account.paths().file_location(
            default_folder.id(),
            id,
            &old_file_name,
        );
        assert!(!vfs::try_exists(&old_file_path).await?);

        *checksum
    } else {
        panic!("expecting file secret variant");
    };

    Ok((*id, new_secret_data, checksum))
}

async fn assert_move_file_secret(
    account: &mut LocalAccount,
    default_folder: &Summary,
    id: &SecretId,
    updated_checksum: &[u8; 32],
    progress_tx: mpsc::Sender<FileProgress>,
) -> Result<(Summary, SecretId, SecretRow, [u8; 32])> {
    let new_folder_name = "Mock folder".to_string();
    let (destination, _, _) = account.create_folder(new_folder_name).await?;

    let (new_id, _) = account
        .move_secret(
            id,
            default_folder,
            &destination,
            AccessOptions {
                folder: None,
                file_progress: Some(progress_tx),
            },
        )
        .await?;

    let (moved_secret_data, _) = account
        .read_secret(&new_id, Some(destination.clone()))
        .await?;

    let checksum = if let Secret::File {
        content:
            FileContent::External {
                mime,
                size,
                checksum,
                path,
                ..
            },
        ..
    } = moved_secret_data.secret()
    {
        assert!(path.is_none());
        assert!(*size > 0);
        assert_ne!(&ZERO, checksum);
        assert_eq!("text/plain", mime);

        assert_eq!(&updated_checksum, &checksum);

        let file_name = hex::encode(checksum);
        let expected_file_path = account.paths().file_location(
            destination.id(),
            &new_id,
            &file_name,
        );
        assert!(vfs::try_exists(&expected_file_path).await?);

        let old_file_path = account.paths().file_location(
            default_folder.id(),
            id,
            &file_name,
        );
        assert!(!vfs::try_exists(&old_file_path).await?);

        *checksum
    } else {
        panic!("expecting file secret variant");
    };

    Ok((destination, new_id, moved_secret_data, checksum))
}

async fn assert_delete_file_secret(
    account: &mut LocalAccount,
    folder: &Summary,
    id: &SecretId,
    checksum: &[u8; 32],
    progress_tx: mpsc::Sender<FileProgress>,
) -> Result<()> {
    let options = AccessOptions {
        folder: Some(folder.clone()),
        file_progress: Some(progress_tx),
    };
    account.delete_secret(id, options).await?;

    // Check deleting the secret also removed the external file
    let file_name = hex::encode(checksum);
    let deleted_file_path =
        account.paths().file_location(folder.id(), id, &file_name);
    assert!(!vfs::try_exists(&deleted_file_path).await?);

    Ok(())
}

async fn assert_create_update_move_file_secret(
    account: &mut LocalAccount,
    default_folder: &Summary,
    progress_tx: mpsc::Sender<FileProgress>,
) -> Result<(Summary, SecretId, [u8; 32])> {
    let (id, secret_data, _) =
        create_file_secret(account, default_folder, progress_tx.clone())
            .await?;

    let original_checksum = if let Secret::File {
        content: FileContent::External { checksum, .. },
        ..
    } = secret_data.secret()
    {
        checksum
    } else {
        panic!("expecting file secret variant");
    };

    let new_folder_name = "Mock folder".to_string();
    let (destination, _, _) = account.create_folder(new_folder_name).await?;

    let new_secret_data = update_file_secret(
        account,
        default_folder,
        &secret_data,
        Some(&destination),
        progress_tx,
    )
    .await?;
    let new_id = *new_secret_data.id();

    let checksum = if let Secret::File {
        content:
            FileContent::External {
                mime,
                size,
                checksum,
                path,
                ..
            },
        ..
    } = new_secret_data.secret()
    {
        assert!(path.is_none());
        assert!(*size > 0);
        assert_ne!(&ZERO, checksum);
        assert_eq!("text/plain", mime);

        let file_name = hex::encode(checksum);
        let expected_file_path = account.paths().file_location(
            destination.id(),
            &new_id,
            &file_name,
        );
        assert!(vfs::try_exists(&expected_file_path).await?);

        let old_file_name = hex::encode(original_checksum);
        let old_file_path = account.paths().file_location(
            default_folder.id(),
            &id,
            &old_file_name,
        );
        assert!(!vfs::try_exists(&old_file_path).await?);

        *checksum
    } else {
        panic!("expecting file secret variant");
    };

    Ok((destination, new_id, checksum))
}

async fn assert_delete_folder_file_secrets(
    account: &mut LocalAccount,
    folder: &Summary,
    id: &SecretId,
    checksum: &[u8; 32],
) -> Result<()> {
    account.delete_folder(folder).await?;

    let file_name = hex::encode(checksum);
    let file_path =
        account.paths().file_location(folder.id(), id, &file_name);
    assert!(!vfs::try_exists(&file_path).await?);

    Ok(())
}

async fn assert_attach_file_secret(
    account: &mut LocalAccount,
    folder: &Summary,
    progress_tx: mpsc::Sender<FileProgress>,
) -> Result<()> {
    let (id, mut secret_data, _) =
        create_file_secret(account, folder, progress_tx.clone()).await?;

    // Add an attachment
    let (meta, secret, _) = mock::file_text_secret()?;
    let attachment_id = SecretId::new_v4();
    let attachment = SecretRow::new(attachment_id, meta, secret);
    secret_data.secret_mut().add_field(attachment);

    account
        .update_secret(
            &id,
            secret_data.meta().clone(),
            Some(secret_data.secret().clone()),
            AccessOptions {
                folder: Some(folder.clone()),
                file_progress: Some(progress_tx.clone()),
            },
            None,
        )
        .await?;

    // Read the secret with attachment
    let (mut secret_data, _) =
        account.read_secret(&id, Some(folder.clone())).await?;

    // We never modify the root secret so assert on every change
    async fn assert_root_file_secret(
        account: &mut LocalAccount,
        folder: &Summary,
        id: &SecretId,
        root: &Secret,
    ) -> Result<()> {
        if let Secret::File {
            content:
                FileContent::External {
                    mime,
                    size,
                    checksum,
                    path,
                    ..
                },
            ..
        } = root
        {
            assert!(path.is_none());
            assert!(*size > 0);
            assert_ne!(&ZERO, checksum);
            assert_eq!("image/heic", mime);

            let file_name = hex::encode(checksum);
            let file_path =
                account.paths().file_location(folder.id(), id, &file_name);
            assert!(vfs::try_exists(&file_path).await?);
        } else {
            panic!("expecting file secret variant");
        };
        Ok(())
    }

    let checksums = if let Secret::File {
        content: FileContent::External { checksum, .. },
        ..
    } = secret_data.secret()
    {
        let file_checksum = *checksum;
        assert_root_file_secret(account, folder, &id, secret_data.secret())
            .await?;

        // Verify the attachment file exists
        let attached = secret_data
            .secret()
            .find_field_by_id(&attachment_id)
            .expect("attachment to exist");

        let attachment_checksum = if let Secret::File {
            content:
                FileContent::External {
                    mime,
                    size,
                    checksum,
                    path,
                    ..
                },
            ..
        } = attached.secret()
        {
            assert!(path.is_none());
            assert!(*size > 0);
            assert_ne!(&ZERO, checksum);
            assert_eq!("text/plain", mime);

            let file_name = hex::encode(checksum);
            let file_path =
                account.paths().file_location(folder.id(), &id, &file_name);
            assert!(vfs::try_exists(&file_path).await?);

            *checksum
        } else {
            panic!("expecting file secret variant (attachment)");
        };

        // Now update the attachment
        let (meta, secret, _) = mock::file_image_secret()?;
        let new_attachment = SecretRow::new(*attached.id(), meta, secret);
        secret_data.secret_mut().update_field(new_attachment)?;
        account
            .update_secret(
                &id,
                secret_data.meta().clone(),
                Some(secret_data.secret().clone()),
                AccessOptions {
                    folder: Some(folder.clone()),
                    file_progress: Some(progress_tx.clone()),
                },
                None,
            )
            .await?;

        assert_root_file_secret(account, folder, &id, secret_data.secret())
            .await?;

        let (mut updated_secret_data, _) =
            account.read_secret(&id, Some(folder.clone())).await?;
        assert_eq!(1, updated_secret_data.secret().user_data().len());

        let updated_attachment = updated_secret_data
            .secret()
            .find_field_by_id(&attachment_id)
            .cloned()
            .expect("attachment to exist");

        let updated_attachment_checksum = if let Secret::File {
            content:
                FileContent::External {
                    mime,
                    size,
                    checksum,
                    path,
                    ..
                },
            ..
        } = updated_attachment.secret()
        {
            assert!(path.is_none());
            assert!(*size > 0);
            assert_ne!(ZERO, *checksum);
            assert_eq!("image/heic", mime);

            let file_name = hex::encode(checksum);
            let file_path =
                account.paths().file_location(folder.id(), &id, &file_name);
            assert!(vfs::try_exists(&file_path).await?);

            let old_file_name = hex::encode(attachment_checksum);
            let old_file_path = account.paths().file_location(
                folder.id(),
                &id,
                &old_file_name,
            );
            assert!(!vfs::try_exists(&old_file_path).await?);

            checksum
        } else {
            panic!("expecting file secret variant (attachment)");
        };

        // Now insert an attachment before the previous one
        let (meta, secret, _) = mock::file_text_secret()?;
        let new_attachment_id = SecretId::new_v4();
        let attachment = SecretRow::new(new_attachment_id, meta, secret);
        updated_secret_data.secret_mut().insert_field(0, attachment);

        let (_, meta, secret) = updated_secret_data.clone().into();
        account
            .update_secret(
                &id,
                meta,
                Some(secret),
                AccessOptions {
                    folder: Some(folder.clone()),
                    file_progress: Some(progress_tx.clone()),
                },
                None,
            )
            .await?;

        assert_root_file_secret(account, folder, &id, secret_data.secret())
            .await?;

        let (mut insert_field_secret_data, _) =
            account.read_secret(&id, Some(folder.clone())).await?;
        assert_eq!(2, insert_field_secret_data.secret().user_data().len());

        let inserted_attachment = insert_field_secret_data
            .secret()
            .find_field_by_id(&new_attachment_id)
            .expect("attachment to exist");

        let original_attachment = insert_field_secret_data
            .secret()
            .find_field_by_id(&attachment_id)
            .expect("attachment to exist");

        let inserted_attachment_checksum = if let Secret::File {
            content: FileContent::External { checksum, .. },
            ..
        } = inserted_attachment.secret()
        {
            assert_ne!(ZERO, *checksum);
            let file_name = hex::encode(checksum);
            let file_path =
                account.paths().file_location(folder.id(), &id, &file_name);
            assert!(vfs::try_exists(&file_path).await?);

            *checksum
        } else {
            panic!("expecting file secret variant (attachment)");
        };

        if let Secret::File {
            content: FileContent::External { checksum, .. },
            ..
        } = original_attachment.secret()
        {
            assert_eq!(updated_attachment_checksum, checksum);
            let file_name = hex::encode(checksum);
            let file_path =
                account.paths().file_location(folder.id(), &id, &file_name);
            assert!(vfs::try_exists(&file_path).await?);
        } else {
            panic!("expecting file secret variant (attachment)");
        };

        // Delete the original attachment (index 1)
        insert_field_secret_data
            .secret_mut()
            .remove_field(&attachment_id);

        let (_, meta, secret) = insert_field_secret_data.into();
        account
            .update_secret(
                &id,
                meta,
                Some(secret),
                AccessOptions {
                    folder: Some(folder.clone()),
                    file_progress: Some(progress_tx.clone()),
                },
                None,
            )
            .await?;

        assert_root_file_secret(account, folder, &id, secret_data.secret())
            .await?;

        let (delete_attachment_secret_data, _) =
            account.read_secret(&id, Some(folder.clone())).await?;
        assert_eq!(
            1,
            delete_attachment_secret_data.secret().user_data().len()
        );

        let updated_inserted_attachment = delete_attachment_secret_data
            .secret()
            .find_field_by_id(&new_attachment_id)
            .expect("attachment to exist");

        if let Secret::File {
            content: FileContent::External { checksum, .. },
            ..
        } = updated_inserted_attachment.secret()
        {
            assert_ne!(&file_checksum, checksum);
            let file_name = hex::encode(checksum);
            let file_path =
                account.paths().file_location(folder.id(), &id, &file_name);
            assert!(vfs::try_exists(&file_path).await?);
        } else {
            panic!("expecting file secret variant (attachment)");
        };

        vec![file_checksum, inserted_attachment_checksum]
    } else {
        panic!("expecting file secret variant");
    };

    // Now delete the secret and check all the files are gone
    account
        .delete_secret(
            &id,
            AccessOptions {
                folder: Some(folder.clone()),
                file_progress: Some(progress_tx.clone()),
            },
        )
        .await?;

    for checksum in checksums {
        let file_path = account.paths().file_location(
            folder.id(),
            &id,
            &hex::encode(checksum),
        );
        assert!(!vfs::try_exists(&file_path).await?);
    }

    Ok(())
}

async fn pause() {
    // Need to pause a bit to give the progress channels some
    // time to flush the messages
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
}
