use anyhow::Result;

use serial_test::serial;
use std::path::PathBuf;

use sos_net::client::{provider::ProviderFactory, user::UserStorage};
use sos_sdk::{
    account::{AccountBuilder, ImportedAccount, NewAccount},
    hex,
    passwd::diceware::generate_passphrase,
    storage::StorageDirs,
    vault::secret::{Secret, SecretMeta},
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

    let file_path = PathBuf::from("tests/fixtures/sample.heic");
    let secret: Secret = file_path.clone().try_into()?;
    let meta = SecretMeta::new("Sample HEIC".to_string(), secret.kind());

    // Create the file secret in the default folder
    let (id, _) = owner
        .create_secret(meta, secret, Some(summary.clone()))
        .await?;
    let (secret_data, _) =
        owner.read_secret(&id, Some(summary.clone())).await?;

    let zero_checksum = [0; 32];
    let original_checksum = if let Secret::File {
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
            owner.file_location(summary.id(), &id, &file_name)?;

        assert!(expected_file_path.exists());

        let source_buffer = std::fs::read(&file_path)?;
        let encrypted_buffer = std::fs::read(&expected_file_path)?;

        assert_ne!(source_buffer, encrypted_buffer);

        checksum
    } else {
        panic!("expecting file secret variant");
    };

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
        owner.read_secret(&id, Some(summary.clone())).await?;

    let updated_checksum = if let Secret::File {
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
            owner.file_location(summary.id(), &id, &file_name)?;
        assert!(expected_file_path.exists());

        let old_file_name = hex::encode(original_checksum);
        let old_file_path =
            owner.file_location(summary.id(), &id, &old_file_name)?;
        assert!(!old_file_path.exists());

        checksum
    } else {
        panic!("expecting file secret variant");
    };

    // Reset the cache dir so we don't interfere
    // with other tests
    StorageDirs::clear_cache_dir();

    Ok(())
}
