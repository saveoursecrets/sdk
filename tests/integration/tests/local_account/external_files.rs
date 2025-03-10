use crate::test_utils::{
    mock::{
        self,
        files::{
            create_attachment, create_file_secret, delete_attachment,
            update_attachment, update_file_secret,
        },
    },
    setup, teardown,
};
use anyhow::Result;
use sos_account::{Account, FolderCreate, LocalAccount, SecretMove};
use sos_client_storage::{AccessOptions, NewFolderOptions};
use sos_core::commit::ZERO;
use sos_core::ExternalFileName;
use sos_external_files::FileProgress;
use sos_sdk::prelude::*;
use sos_test_utils::make_client_backend;
use sos_vfs as vfs;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Tests for the external file logic for a local account.
#[tokio::test]
async fn local_external_files() -> Result<()> {
    const TEST_ID: &str = "external_files";
    //crate::test_utils::init_tracing();

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

async fn assert_create_file_secret(
    account: &mut LocalAccount,
    default_folder: &Summary,
    progress_tx: mpsc::Sender<FileProgress>,
) -> Result<(SecretId, SecretRow, [u8; 32])> {
    let (id, secret_data, file_path, _) =
        create_file_secret(account, default_folder, Some(progress_tx))
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
    } = secret_data.secret()
    {
        assert!(path.is_none());
        assert!(*size > 0);
        assert_ne!(&ZERO, checksum);
        assert_eq!("image/heic", mime);

        let file_name = ExternalFileName::from(checksum);
        let paths = account.paths();
        let expected_file_path =
            paths.into_file_path_parts(default_folder.id(), &id, &file_name);

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
    let (new_secret_data, _) = update_file_secret(
        account,
        default_folder,
        secret_data,
        None,
        Some(progress_tx),
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

        let file_name = ExternalFileName::from(checksum);
        let paths = account.paths();
        let expected_file_path =
            paths.into_file_path_parts(default_folder.id(), id, &file_name);

        assert!(vfs::try_exists(&expected_file_path).await?);

        let old_file_name = ExternalFileName::from(original_checksum);
        let old_file_path = paths.into_file_path_parts(
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
    let FolderCreate {
        folder: destination,
        ..
    } = account
        .create_folder(NewFolderOptions::new(new_folder_name.to_owned()))
        .await?;

    let SecretMove { id: new_id, .. } = account
        .move_secret(
            id,
            default_folder.id(),
            destination.id(),
            AccessOptions {
                folder: None,
                file_progress: Some(progress_tx),
                ..Default::default()
            },
        )
        .await?;

    let (moved_secret_data, _) =
        account.read_secret(&new_id, Some(destination.id())).await?;

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

        let file_name = ExternalFileName::from(checksum);
        let paths = account.paths();

        let expected_file_path =
            paths.into_file_path_parts(destination.id(), &new_id, &file_name);

        assert!(vfs::try_exists(&expected_file_path).await?);

        let old_file_path =
            paths.into_file_path_parts(default_folder.id(), id, &file_name);
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
        folder: Some(*folder.id()),
        file_progress: Some(progress_tx),
        ..Default::default()
    };
    account.delete_secret(id, options).await?;

    // Check deleting the secret also removed the external file
    let file_name = ExternalFileName::from(checksum);
    let paths = account.paths();
    let deleted_file_path =
        paths.into_file_path_parts(folder.id(), id, &file_name);
    assert!(!vfs::try_exists(&deleted_file_path).await?);

    Ok(())
}

async fn assert_create_update_move_file_secret(
    account: &mut LocalAccount,
    default_folder: &Summary,
    progress_tx: mpsc::Sender<FileProgress>,
) -> Result<(Summary, SecretId, [u8; 32])> {
    let (id, secret_data, _, _) = create_file_secret(
        account,
        default_folder,
        Some(progress_tx.clone()),
    )
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
    let FolderCreate {
        folder: destination,
        ..
    } = account
        .create_folder(NewFolderOptions::new(new_folder_name.to_owned()))
        .await?;

    let (new_secret_data, _) = update_file_secret(
        account,
        default_folder,
        &secret_data,
        Some(&destination),
        Some(progress_tx),
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

        let file_name = ExternalFileName::from(checksum);

        let paths = account.paths();
        let expected_file_path =
            paths.into_file_path_parts(destination.id(), &new_id, &file_name);

        assert!(vfs::try_exists(&expected_file_path).await?);

        let old_file_name = ExternalFileName::from(original_checksum);
        let old_file_path = paths.into_file_path_parts(
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
    account.delete_folder(folder.id()).await?;

    let file_name = ExternalFileName::from(checksum);
    let paths = account.paths();
    let file_path = paths.into_file_path_parts(folder.id(), id, &file_name);

    assert!(!vfs::try_exists(&file_path).await?);

    Ok(())
}

async fn assert_attach_file_secret(
    account: &mut LocalAccount,
    folder: &Summary,
    progress_tx: mpsc::Sender<FileProgress>,
) -> Result<()> {
    let (id, _, _, _) =
        create_file_secret(account, folder, Some(progress_tx.clone()))
            .await?;

    // Add an attachment
    let (attachment_id, mut secret_data, file_name) =
        create_attachment(account, &id, &folder, Some(progress_tx.clone()))
            .await?;

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

            let file_name = ExternalFileName::from(checksum);
            let paths = account.paths();
            let file_path =
                paths.into_file_path_parts(folder.id(), id, &file_name);
            assert!(vfs::try_exists(&file_path).await?);
        } else {
            panic!("expecting file secret variant");
        };
        Ok(())
    }

    let file_names = if let Secret::File {
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

            let file_name = ExternalFileName::from(checksum);
            let paths = account.paths();
            let file_path =
                paths.into_file_path_parts(folder.id(), &id, &file_name);
            assert!(vfs::try_exists(&file_path).await?);

            *checksum
        } else {
            panic!("expecting file secret variant (attachment)");
        };

        // Now update the attachment
        let attachment_id = *attached.id();
        let (mut updated_secret_data, updated_attachment, _) =
            update_attachment(
                account,
                &mut secret_data,
                &attachment_id,
                &folder,
                Some(progress_tx.clone()),
            )
            .await?;

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

            let file_name = ExternalFileName::from(checksum);
            let paths = account.paths();
            let file_path =
                paths.into_file_path_parts(folder.id(), &id, &file_name);
            assert!(vfs::try_exists(&file_path).await?);

            let old_file_name = ExternalFileName::from(attachment_checksum);
            let old_file_path =
                paths.into_file_path_parts(folder.id(), &id, &old_file_name);
            assert!(!vfs::try_exists(&old_file_path).await?);

            checksum
        } else {
            panic!("expecting file secret variant (attachment)");
        };

        assert_root_file_secret(account, folder, &id, secret_data.secret())
            .await?;

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
                    folder: Some(*folder.id()),
                    file_progress: Some(progress_tx.clone()),
                    ..Default::default()
                },
            )
            .await?;

        assert_root_file_secret(account, folder, &id, secret_data.secret())
            .await?;

        let (insert_field_secret_data, _) =
            account.read_secret(&id, Some(folder.id())).await?;
        assert_eq!(2, insert_field_secret_data.secret().user_data().len());

        let inserted_attachment = insert_field_secret_data
            .secret()
            .find_field_by_id(&new_attachment_id)
            .expect("attachment to exist");

        let original_attachment = insert_field_secret_data
            .secret()
            .find_field_by_id(&attachment_id)
            .expect("attachment to exist");

        let inserted_attachment_name: ExternalFileName =
            if let Secret::File {
                content: FileContent::External { checksum, .. },
                ..
            } = inserted_attachment.secret()
            {
                assert_ne!(ZERO, *checksum);
                let file_name = ExternalFileName::from(checksum);

                let paths = account.paths();
                let file_path =
                    paths.into_file_path_parts(folder.id(), &id, &file_name);

                assert!(vfs::try_exists(&file_path).await?);

                (*checksum).into()
            } else {
                panic!("expecting file secret variant (attachment)");
            };

        if let Secret::File {
            content: FileContent::External { checksum, .. },
            ..
        } = original_attachment.secret()
        {
            assert_eq!(updated_attachment_checksum, checksum);
            let file_name = ExternalFileName::from(checksum);
            let paths = account.paths();
            let file_path =
                paths.into_file_path_parts(folder.id(), &id, &file_name);

            assert!(vfs::try_exists(&file_path).await?);
        } else {
            panic!("expecting file secret variant (attachment)");
        };

        // Delete the original attachment (index 1)
        delete_attachment(
            account,
            insert_field_secret_data,
            &attachment_id,
            &folder,
            Some(progress_tx.clone()),
        )
        .await?;

        assert_root_file_secret(account, folder, &id, secret_data.secret())
            .await?;

        let (delete_attachment_secret_data, _) =
            account.read_secret(&id, Some(folder.id())).await?;
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
            let file_name = ExternalFileName::from(checksum);

            let paths = account.paths();
            let file_path =
                paths.into_file_path_parts(folder.id(), &id, &file_name);

            assert!(vfs::try_exists(&file_path).await?);
        } else {
            panic!("expecting file secret variant (attachment)");
        };

        vec![file_name, inserted_attachment_name]
    } else {
        panic!("expecting file secret variant");
    };

    // Now delete the secret and check all the files are gone
    account
        .delete_secret(
            &id,
            AccessOptions {
                folder: Some(*folder.id()),
                file_progress: Some(progress_tx.clone()),
                ..Default::default()
            },
        )
        .await?;

    let paths = account.paths();
    for file_name in file_names {
        let file_path =
            paths.into_file_path_parts(folder.id(), &id, &file_name);
        assert!(!vfs::try_exists(&file_path).await?);
    }

    Ok(())
}

async fn pause() {
    // Need to pause a bit to give the progress channels some
    // time to flush the messages
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
}
