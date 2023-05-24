use anyhow::Result;

use serial_test::serial;
use std::path::PathBuf;

use sos_net::client::{provider::ProviderFactory, user::UserStorage};
use sos_sdk::{
    account::{AccountBuilder, ImportedAccount, NewAccount},
    hex,
    passwd::diceware::generate_passphrase,
    storage::StorageDirs,
    vault::{
        secret::{
            FileContent, Secret, SecretData, SecretId, SecretMeta, SecretRow,
        },
        Summary,
    },
    vfs,
};

use crate::test_utils::setup;

const ZERO_CHECKSUM: [u8; 32] = [0; 32];

#[tokio::test]
#[serial]
async fn integration_external_files() -> Result<()> {
    let dirs = setup(1)?;

    let test_cache_dir = dirs.clients.get(0).unwrap();
    StorageDirs::set_cache_dir(test_cache_dir.clone());
    assert_eq!(StorageDirs::cache_dir(), Some(test_cache_dir.clone()));
    StorageDirs::skeleton().await?;

    let account_name = "External files test".to_string();
    let (passphrase, _) = generate_passphrase()?;

    let new_account =
        AccountBuilder::new(account_name.clone(), passphrase.clone())
            .save_passphrase(true)
            .create_archive(true)
            .create_authenticator(false)
            .create_contacts(false)
            .create_file_password(true)
            .finish()
            .await?;

    let factory = ProviderFactory::Local;
    let (mut provider, _) = factory
        .create_provider(new_account.user.signer().clone())
        .await?;
    provider.dirs().ensure().await?;

    let imported_account = provider.import_new_account(&new_account).await?;
    let NewAccount { address, .. } = new_account;
    let ImportedAccount { summary, .. } = imported_account;

    let mut owner = UserStorage::new(&address, passphrase, factory).await?;
    owner.initialize_search_index().await?;

    let (id, secret_data, original_checksum) =
        assert_create_file_secret(&mut owner, &summary).await?;

    let (new_id, _new_secret_data, updated_checksum) =
        assert_update_file_secret(
            &mut owner,
            &summary,
            &id,
            &secret_data,
            &original_checksum,
        )
        .await?;

    let (destination, moved_id, _moved_secret_data, moved_checksum) =
        assert_move_file_secret(
            &mut owner,
            &summary,
            &new_id,
            &updated_checksum,
        )
        .await?;

    assert_delete_file_secret(
        &mut owner,
        &destination,
        &moved_id,
        &moved_checksum,
    )
    .await?;

    let (destination, id, checksum) =
        assert_create_update_move_file_secret(&mut owner, &summary).await?;

    assert_delete_folder_file_secrets(
        &mut owner,
        &destination,
        &id,
        &checksum,
    )
    .await?;

    assert_attach_file_secret(&mut owner, &summary).await?;

    // Reset the cache dir so we don't interfere
    // with other tests
    StorageDirs::clear_cache_dir();

    Ok(())
}

fn get_image_secret() -> Result<(SecretMeta, Secret, PathBuf)> {
    let file_path = PathBuf::from("tests/fixtures/sample.heic");
    let secret: Secret = file_path.clone().try_into()?;
    let meta =
        SecretMeta::new("Sample image file".to_string(), secret.kind());
    Ok((meta, secret, file_path))
}

fn get_text_secret() -> Result<(SecretMeta, Secret, PathBuf)> {
    let file_path = PathBuf::from("tests/fixtures/test-file.txt");
    let secret: Secret = file_path.clone().try_into()?;
    let meta = SecretMeta::new("Sample text file".to_string(), secret.kind());
    Ok((meta, secret, file_path))
}

async fn create_file_secret(
    owner: &mut UserStorage,
    default_folder: &Summary,
) -> Result<(SecretId, SecretData, PathBuf)> {
    let (meta, secret, file_path) = get_image_secret()?;

    // Create the file secret in the default folder
    let (id, _) = owner
        .create_secret(meta, secret, Some(default_folder.clone()))
        .await?;
    let (secret_data, _) =
        owner.read_secret(&id, Some(default_folder.clone())).await?;

    Ok((id, secret_data, file_path))
}

async fn update_file_secret(
    owner: &mut UserStorage,
    default_folder: &Summary,
    secret_data: &SecretData,
    destination: Option<&Summary>,
) -> Result<SecretData> {
    let id = secret_data.id.as_ref().unwrap();

    let mut new_meta = secret_data.meta.clone();
    new_meta.set_label("Text file".to_string());

    let (new_id, _) = owner
        .update_file(
            id,
            new_meta,
            "tests/fixtures/test-file.txt",
            None,
            destination,
        )
        .await?;

    let folder = destination
        .cloned()
        .unwrap_or_else(|| default_folder.clone());
    let (new_secret_data, _) =
        owner.read_secret(&new_id, Some(folder)).await?;

    Ok(new_secret_data)
}

async fn assert_create_file_secret(
    owner: &mut UserStorage,
    default_folder: &Summary,
) -> Result<(SecretId, SecretData, [u8; 32])> {
    let (id, secret_data, file_path) =
        create_file_secret(owner, default_folder).await?;

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
    } = &secret_data.secret
    {
        assert!(path.is_none());
        assert!(*size > 0);
        assert_ne!(&ZERO_CHECKSUM, checksum);
        assert_eq!("image/heic", mime);

        let file_name = hex::encode(checksum);
        let expected_file_path =
            owner.file_location(default_folder.id(), &id, &file_name)?;

        assert!(expected_file_path.exists());

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
    owner: &mut UserStorage,
    default_folder: &Summary,
    id: &SecretId,
    secret_data: &SecretData,
    original_checksum: &[u8; 32],
) -> Result<(SecretId, SecretData, [u8; 32])> {
    let new_secret_data =
        update_file_secret(owner, default_folder, secret_data, None).await?;

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
    } = &new_secret_data.secret
    {
        assert!(path.is_none());
        assert!(*size > 0);
        assert_ne!(&ZERO_CHECKSUM, checksum);
        assert_eq!("text/plain", mime);

        let file_name = hex::encode(checksum);
        let expected_file_path =
            owner.file_location(default_folder.id(), id, &file_name)?;
        assert!(expected_file_path.exists());

        let old_file_name = hex::encode(original_checksum);
        let old_file_path =
            owner.file_location(default_folder.id(), id, &old_file_name)?;
        assert!(!old_file_path.exists());

        *checksum
    } else {
        panic!("expecting file secret variant");
    };

    Ok((*id, new_secret_data, checksum))
}

async fn assert_move_file_secret(
    owner: &mut UserStorage,
    default_folder: &Summary,
    id: &SecretId,
    updated_checksum: &[u8; 32],
) -> Result<(Summary, SecretId, SecretData, [u8; 32])> {
    let new_folder_name = "Mock folder".to_string();
    let destination = owner.create_folder(new_folder_name).await?;

    let (new_id, _, _, _) =
        owner.move_secret(id, default_folder, &destination).await?;

    let (moved_secret_data, _) = owner
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
    } = &moved_secret_data.secret
    {
        assert!(path.is_none());
        assert!(*size > 0);
        assert_ne!(&ZERO_CHECKSUM, checksum);
        assert_eq!("text/plain", mime);

        assert_eq!(&updated_checksum, &checksum);

        let file_name = hex::encode(checksum);
        let expected_file_path =
            owner.file_location(destination.id(), &new_id, &file_name)?;
        assert!(expected_file_path.exists());

        let old_file_path =
            owner.file_location(default_folder.id(), id, &file_name)?;
        assert!(!old_file_path.exists());

        *checksum
    } else {
        panic!("expecting file secret variant");
    };

    Ok((destination, new_id, moved_secret_data, checksum))
}

async fn assert_delete_file_secret(
    owner: &mut UserStorage,
    folder: &Summary,
    id: &SecretId,
    checksum: &[u8; 32],
) -> Result<()> {
    owner.delete_secret(id, Some(folder.clone())).await?;

    // Check deleting the secret also removed the external file
    let file_name = hex::encode(checksum);
    let deleted_file_path =
        owner.file_location(folder.id(), id, &file_name)?;
    assert!(!deleted_file_path.exists());

    Ok(())
}

async fn assert_create_update_move_file_secret(
    owner: &mut UserStorage,
    default_folder: &Summary,
) -> Result<(Summary, SecretId, [u8; 32])> {
    let (id, secret_data, _) =
        create_file_secret(owner, default_folder).await?;

    let original_checksum = if let Secret::File {
        content: FileContent::External { checksum, .. },
        ..
    } = &secret_data.secret
    {
        checksum
    } else {
        panic!("expecting file secret variant");
    };

    let new_folder_name = "Mock folder".to_string();
    let destination = owner.create_folder(new_folder_name).await?;

    let new_secret_data = update_file_secret(
        owner,
        default_folder,
        &secret_data,
        Some(&destination),
    )
    .await?;
    let new_id = new_secret_data.id.as_ref().unwrap();

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
    } = &new_secret_data.secret
    {
        assert!(path.is_none());
        assert!(*size > 0);
        assert_ne!(&ZERO_CHECKSUM, checksum);
        assert_eq!("text/plain", mime);

        let file_name = hex::encode(checksum);
        let expected_file_path =
            owner.file_location(destination.id(), new_id, &file_name)?;
        assert!(expected_file_path.exists());

        let old_file_name = hex::encode(original_checksum);
        let old_file_path =
            owner.file_location(default_folder.id(), &id, &old_file_name)?;
        assert!(!old_file_path.exists());

        *checksum
    } else {
        panic!("expecting file secret variant");
    };

    Ok((destination, *new_id, checksum))
}

async fn assert_delete_folder_file_secrets(
    owner: &mut UserStorage,
    folder: &Summary,
    id: &SecretId,
    checksum: &[u8; 32],
) -> Result<()> {
    owner.delete_folder(folder).await?;

    let file_name = hex::encode(checksum);
    let file_path = owner.file_location(folder.id(), id, &file_name)?;
    assert!(!file_path.exists());

    Ok(())
}

async fn assert_attach_file_secret(
    owner: &mut UserStorage,
    folder: &Summary,
) -> Result<()> {
    let (id, mut secret_data, _) = create_file_secret(owner, folder).await?;

    // Add an attachment
    let (meta, secret, _) = get_text_secret()?;
    let attachment_id = SecretId::new_v4();
    let attachment = SecretRow::new(attachment_id, meta, secret);
    secret_data.secret.attach(attachment);

    owner
        .update_secret(
            &id,
            secret_data.meta,
            Some(secret_data.secret),
            Some(folder.clone()),
            None,
        )
        .await?;

    // Read the secret with attachment
    let (mut secret_data, _) =
        owner.read_secret(&id, Some(folder.clone())).await?;

    // We never modify the root secret so assert on every change
    fn assert_root_file_secret(
        owner: &mut UserStorage,
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
            assert_ne!(&ZERO_CHECKSUM, checksum);
            assert_eq!("image/heic", mime);

            let file_name = hex::encode(checksum);
            let file_path =
                owner.file_location(folder.id(), id, &file_name)?;
            assert!(file_path.exists());
        } else {
            panic!("expecting file secret variant");
        };
        Ok(())
    }

    let checksums = if let Secret::File {
        content: FileContent::External { checksum, .. },
        ..
    } = &secret_data.secret
    {
        let file_checksum = *checksum;
        assert_root_file_secret(owner, folder, &id, &secret_data.secret)?;

        // Verify the attachment file exists
        let attached = secret_data
            .secret
            .find_attachment_by_id(&attachment_id)
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
            assert_ne!(&ZERO_CHECKSUM, checksum);
            assert_eq!("text/plain", mime);

            let file_name = hex::encode(checksum);
            let file_path =
                owner.file_location(folder.id(), &id, &file_name)?;
            assert!(file_path.exists());

            *checksum
        } else {
            panic!("expecting file secret variant (attachment)");
        };

        // Now update the attachment
        let (meta, secret, _) = get_image_secret()?;
        let new_attachment = SecretRow::new(*attached.id(), meta, secret);
        secret_data.secret.update_attachment(new_attachment)?;
        owner
            .update_secret(
                &id,
                secret_data.meta.clone(),
                Some(secret_data.secret.clone()),
                Some(folder.clone()),
                None,
            )
            .await?;

        assert_root_file_secret(owner, folder, &id, &secret_data.secret)?;

        let (mut updated_secret_data, _) =
            owner.read_secret(&id, Some(folder.clone())).await?;
        assert_eq!(1, updated_secret_data.secret.user_data().len());

        let updated_attachment = updated_secret_data
            .secret
            .find_attachment_by_id(&attachment_id)
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
            assert_ne!(&ZERO_CHECKSUM, checksum);
            assert_eq!("image/heic", mime);

            let file_name = hex::encode(checksum);
            let file_path =
                owner.file_location(folder.id(), &id, &file_name)?;
            assert!(file_path.exists());

            let old_file_name = hex::encode(attachment_checksum);
            let old_file_path =
                owner.file_location(folder.id(), &id, &old_file_name)?;
            assert!(!old_file_path.exists());

            *checksum
        } else {
            panic!("expecting file secret variant (attachment)");
        };

        // Now insert an attachment before the previous one
        let (meta, secret, _) = get_text_secret()?;
        let new_attachment_id = SecretId::new_v4();
        let attachment = SecretRow::new(new_attachment_id, meta, secret);
        updated_secret_data.secret.insert_attachment(0, attachment);

        owner
            .update_secret(
                &id,
                updated_secret_data.meta,
                Some(updated_secret_data.secret),
                Some(folder.clone()),
                None,
            )
            .await?;

        assert_root_file_secret(owner, folder, &id, &secret_data.secret)?;

        let (mut insert_attachment_secret_data, _) =
            owner.read_secret(&id, Some(folder.clone())).await?;
        assert_eq!(2, insert_attachment_secret_data.secret.user_data().len());

        let inserted_attachment = insert_attachment_secret_data
            .secret
            .find_attachment_by_id(&new_attachment_id)
            .expect("attachment to exist");

        let original_attachment = insert_attachment_secret_data
            .secret
            .find_attachment_by_id(&attachment_id)
            .expect("attachment to exist");

        let inserted_attachment_checksum = if let Secret::File {
            content: FileContent::External { checksum, .. },
            ..
        } = inserted_attachment.secret()
        {
            assert_ne!(&ZERO_CHECKSUM, checksum);
            let file_name = hex::encode(checksum);
            let file_path =
                owner.file_location(folder.id(), &id, &file_name)?;
            assert!(file_path.exists());

            *checksum
        } else {
            panic!("expecting file secret variant (attachment)");
        };

        if let Secret::File {
            content: FileContent::External { checksum, .. },
            ..
        } = original_attachment.secret()
        {
            assert_eq!(&updated_attachment_checksum, checksum);
            let file_name = hex::encode(checksum);
            let file_path =
                owner.file_location(folder.id(), &id, &file_name)?;
            assert!(file_path.exists());
        } else {
            panic!("expecting file secret variant (attachment)");
        };

        // Delete the original attachment (index 1)
        insert_attachment_secret_data.secret.detach(&attachment_id);

        owner
            .update_secret(
                &id,
                insert_attachment_secret_data.meta,
                Some(insert_attachment_secret_data.secret),
                Some(folder.clone()),
                None,
            )
            .await?;

        assert_root_file_secret(owner, folder, &id, &secret_data.secret)?;

        let (delete_attachment_secret_data, _) =
            owner.read_secret(&id, Some(folder.clone())).await?;
        assert_eq!(1, delete_attachment_secret_data.secret.user_data().len());

        let updated_inserted_attachment = delete_attachment_secret_data
            .secret
            .find_attachment_by_id(&new_attachment_id)
            .expect("attachment to exist");

        if let Secret::File {
            content: FileContent::External { checksum, .. },
            ..
        } = updated_inserted_attachment.secret()
        {
            assert_ne!(&file_checksum, checksum);
            let file_name = hex::encode(checksum);
            let file_path =
                owner.file_location(folder.id(), &id, &file_name)?;
            assert!(file_path.exists());
        } else {
            panic!("expecting file secret variant (attachment)");
        };

        vec![file_checksum, inserted_attachment_checksum]
    } else {
        panic!("expecting file secret variant");
    };

    // Now delete the secret and check all the files are gone
    owner.delete_secret(&id, Some(folder.clone())).await?;

    for checksum in checksums {
        let file_path =
            owner.file_location(folder.id(), &id, &hex::encode(checksum))?;
        assert!(!file_path.exists());
    }

    Ok(())
}
