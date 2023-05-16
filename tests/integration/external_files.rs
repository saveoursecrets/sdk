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
        secret::{Secret, SecretData, SecretId, SecretMeta},
        Summary,
    },
};

use crate::test_utils::setup;

#[tokio::test]
#[serial]
async fn integration_external_files() -> Result<()> {
    let dirs = setup(1)?;

    let test_cache_dir = dirs.clients.get(0).unwrap();
    StorageDirs::set_cache_dir(test_cache_dir.clone());

    assert_eq!(StorageDirs::cache_dir(), Some(test_cache_dir.clone()));

    let account_name = "External files test".to_string();
    let (passphrase, _) = generate_passphrase()?;

    let new_account =
        AccountBuilder::new(account_name.clone(), passphrase.clone())
            .save_passphrase(true)
            .create_archive(true)
            .create_authenticator(false)
            .create_contacts(false)
            .create_file_password(true)
            .finish()?;

    let factory = ProviderFactory::Local;
    let (mut provider, _) =
        factory.create_provider(new_account.user.signer().clone())?;

    let imported_account = provider.import_new_account(&new_account).await?;
    let NewAccount { address, .. } = new_account;
    let ImportedAccount { summary, .. } = imported_account;

    let mut owner = UserStorage::new(&address, passphrase, factory).await?;
    owner.initialize_search_index().await?;

    let (id, secret_data, original_checksum) =
        assert_create_file_secret(&mut owner, &summary).await?;

    let (new_id, new_secret_data, updated_checksum) =
        assert_update_file_secret(
            &mut owner,
            &summary,
            &id,
            &secret_data,
            &original_checksum,
        )
        .await?;

    let (moved_id, moved_secret_data, moved_checksum, destination) =
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

    assert_create_update_move_file_secret(&mut owner, &summary).await?;

    // Reset the cache dir so we don't interfere
    // with other tests
    StorageDirs::clear_cache_dir();

    Ok(())
}

async fn create_file_secret(
    owner: &mut UserStorage,
    default_folder: &Summary,
) -> Result<(SecretId, SecretData, PathBuf)> {
    let file_path = PathBuf::from("tests/fixtures/sample.heic");
    let secret: Secret = file_path.clone().try_into()?;
    let meta = SecretMeta::new("Sample HEIC".to_string(), secret.kind());

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
            &id,
            new_meta,
            "tests/fixtures/test-file.txt",
            None,
            destination,
        )
        .await?;

    let folder = destination
        .map(|s| s.clone())
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

    let zero_checksum = [0; 32];
    let checksum = if let Secret::File {
        mime,
        external,
        size,
        checksum,
        path,
        ..
    } = &secret_data.secret
    {
        assert!(path.is_none());
        assert!(*size > 0);
        assert!(external);
        assert_ne!(&zero_checksum, checksum);
        assert_eq!("image/heic", mime);

        let file_name = hex::encode(checksum);
        let expected_file_path =
            owner.file_location(default_folder.id(), &id, &file_name)?;

        assert!(expected_file_path.exists());

        let source_buffer = std::fs::read(&file_path)?;
        let encrypted_buffer = std::fs::read(&expected_file_path)?;

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
    /*
    let mut new_meta = secret_data.meta.clone();
    new_meta.set_label("Text file".to_string());

    owner
        .update_file(
            &id,
            new_meta,
            "tests/fixtures/test-file.txt",
            None,
            None,
        )
        .await?;
    let (new_secret_data, _) =
        owner.read_secret(&id, Some(default_folder.clone())).await?;
    */

    let new_secret_data =
        update_file_secret(owner, default_folder, secret_data, None).await?;

    let zero_checksum = [0; 32];
    let checksum = if let Secret::File {
        mime,
        external,
        size,
        checksum,
        path,
        ..
    } = &new_secret_data.secret
    {
        assert!(path.is_none());
        assert!(*size > 0);
        assert!(external);
        assert_ne!(&zero_checksum, checksum);
        assert_eq!("text/plain", mime);

        let file_name = hex::encode(checksum);
        let expected_file_path =
            owner.file_location(default_folder.id(), &id, &file_name)?;
        assert!(expected_file_path.exists());

        let old_file_name = hex::encode(original_checksum);
        let old_file_path =
            owner.file_location(default_folder.id(), &id, &old_file_name)?;
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
) -> Result<(SecretId, SecretData, [u8; 32], Summary)> {
    let new_folder_name = "Mock folder".to_string();
    let destination = owner.create_folder(new_folder_name).await?;

    let (new_id, _, _, _) = owner
        .move_secret(&id, &default_folder, &destination)
        .await?;

    let (moved_secret_data, _) = owner
        .read_secret(&new_id, Some(destination.clone()))
        .await?;

    let zero_checksum = [0; 32];
    let checksum = if let Secret::File {
        mime,
        external,
        size,
        checksum,
        path,
        ..
    } = &moved_secret_data.secret
    {
        assert!(path.is_none());
        assert!(*size > 0);
        assert!(external);
        assert_ne!(&zero_checksum, checksum);
        assert_eq!("text/plain", mime);

        assert_eq!(&updated_checksum, &checksum);

        let file_name = hex::encode(checksum);
        let expected_file_path =
            owner.file_location(destination.id(), &new_id, &file_name)?;
        assert!(expected_file_path.exists());

        let old_file_path =
            owner.file_location(default_folder.id(), &id, &file_name)?;
        assert!(!old_file_path.exists());

        *checksum
    } else {
        panic!("expecting file secret variant");
    };

    Ok((new_id, moved_secret_data, checksum, destination))
}

async fn assert_delete_file_secret(
    owner: &mut UserStorage,
    folder: &Summary,
    id: &SecretId,
    checksum: &[u8; 32],
) -> Result<()> {
    owner.delete_secret(&id, Some(folder.clone())).await?;

    // Check deleting the secret also removed the external file
    let file_name = hex::encode(checksum);
    let deleted_file_path =
        owner.file_location(folder.id(), &id, &file_name)?;
    assert!(!deleted_file_path.exists());

    Ok(())
}

async fn assert_create_update_move_file_secret(
    owner: &mut UserStorage,
    default_folder: &Summary,
) -> Result<()> {
    let (id, secret_data, _) =
        create_file_secret(owner, default_folder).await?;

    let original_checksum =
        if let Secret::File { checksum, .. } = &secret_data.secret {
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

    let zero_checksum = [0; 32];
    if let Secret::File {
        mime,
        external,
        size,
        checksum,
        path,
        ..
    } = &new_secret_data.secret
    {
        assert!(path.is_none());
        assert!(*size > 0);
        assert!(external);
        assert_ne!(&zero_checksum, checksum);
        assert_eq!("text/plain", mime);

        let file_name = hex::encode(checksum);
        let expected_file_path =
            owner.file_location(destination.id(), &new_id, &file_name)?;
        assert!(expected_file_path.exists());

        let old_file_name = hex::encode(original_checksum);
        let old_file_path =
            owner.file_location(default_folder.id(), &id, &old_file_name)?;
        assert!(!old_file_path.exists());
    } else {
        panic!("expecting file secret variant");
    };

    Ok(())
}
