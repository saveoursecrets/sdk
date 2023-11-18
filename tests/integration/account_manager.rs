use anyhow::Result;

use serial_test::serial;
use std::{io::Cursor, path::PathBuf, sync::Arc};

use sos_net::{
    client::provider::new_local_provider,
    sdk::{
        account::{
            AccountBackup, AccountBuilder, DelegatedPassphrase,
            ExtractFilesLocation, ImportedAccount, LocalAccounts, Login,
            NewAccount, RestoreOptions,
        },
        constants::{LOGIN_AGE_KEY_URN, LOGIN_SIGNING_KEY_URN},
        hex,
        passwd::diceware::generate_passphrase,
        search::SearchIndex,
        storage::{AppPaths, FileStorage, UserPaths},
        urn::Urn,
        vault::{secret::SecretId, Gatekeeper, VaultId},
        vfs,
    },
};
use tokio::sync::RwLock;

use crate::test_utils::*;

#[tokio::test]
#[serial]
async fn integration_account_manager() -> Result<()> {
    let dirs = setup(1).await?;

    let test_data_dir = dirs.clients.get(0).unwrap();
    AppPaths::set_data_dir(test_data_dir.clone());
    assert_eq!(AppPaths::data_dir()?, test_data_dir.clone().join("debug"));
    AppPaths::scaffold().await?;

    let account_name = "Mock account name".to_string();
    let folder_name = Some("Default folder".to_string());
    let (passphrase, _) = generate_passphrase()?;

    let new_account =
        AccountBuilder::new(account_name.clone(), passphrase.clone())
            .save_passphrase(true)
            .create_archive(true)
            .create_authenticator(true)
            .create_contacts(true)
            .create_file_password(true)
            .default_folder_name(folder_name)
            .finish()
            .await?;

    // Create local provider
    let signer = new_account.user.signer().clone();
    let (mut provider, _) = new_local_provider(signer, None).await?;

    let (imported_account, _) =
        provider.import_new_account(&new_account).await?;

    let NewAccount { address, .. } = new_account;
    let ImportedAccount { summary, .. } = imported_account;

    let paths = UserPaths::new(
        AppPaths::data_dir()?, &address.to_string());
    let local_accounts = LocalAccounts::new(&paths);

    let accounts = LocalAccounts::list_accounts().await?;
    assert_eq!(1, accounts.len());

    let identity_index = Arc::new(RwLock::new(SearchIndex::new()));
    let mut user = Login::sign_in(
        &address,
        &paths,
        passphrase.clone(),
        Arc::clone(&identity_index),
    )
    .await?;

    user.rename_account(&paths, "New account name".to_string()).await?;
    assert_eq!("New account name", user.identity().keeper().vault().name());

    let vaults = local_accounts.list_local_vaults(false).await?;
    // Default, Contacts, Authenticator and Archive vaults
    assert_eq!(4, vaults.len());

    let identity_reader = identity_index.read().await;

    // Check we can find the signing key
    let signing_urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
    let signing_key = identity_reader
        .find_by_urn(user.identity().keeper().id(), &signing_urn);
    assert!(signing_key.is_some());

    // Check AGE key
    let age_urn: Urn = LOGIN_AGE_KEY_URN.parse()?;
    let age_key =
        identity_reader.find_by_urn(user.identity().keeper().id(), &age_urn);
    assert!(age_key.is_some());

    // Make sure we can find a vault passphrase and unlock it
    let default_vault_passphrase =
        DelegatedPassphrase::find_vault_passphrase(
            user.identity().keeper(),
            summary.id(),
        )
        .await?;

    let default_index = Arc::new(RwLock::new(SearchIndex::new()));
    let (default_vault, _) =
        local_accounts.find_local_vault(summary.id(), false)
            .await?;
    let mut default_vault_keeper =
        Gatekeeper::new(default_vault, Some(default_index));
    default_vault_keeper
        .unlock(default_vault_passphrase.clone())
        .await?;

    let file_passphrase =
        DelegatedPassphrase::find_file_encryption_passphrase(
            user.identity().keeper(),
        )
        .await?;
    let source_file = PathBuf::from("tests/fixtures/test-file.txt");

    // Encrypt
    let files_dir = paths.files_dir();
    let vault_id = VaultId::new_v4();
    let secret_id = SecretId::new_v4();
    let target = files_dir
        .join(vault_id.to_string())
        .join(secret_id.to_string());
    vfs::create_dir_all(&target).await?;
    let (digest, _) = FileStorage::encrypt_file_passphrase(
        &source_file,
        &target,
        file_passphrase.clone(),
    )
    .await?;

    // Decrypt
    let destination = target.join(hex::encode(digest));
    let buffer =
        FileStorage::decrypt_file_passphrase(destination, &file_passphrase)
            .await?;

    let expected = vfs::read(source_file).await?;
    assert_eq!(expected, buffer);

    let mut archive_buffer =
        AccountBackup::export_archive_buffer(&address, &paths).await?;
    let reader = Cursor::new(&mut archive_buffer);
    let _inventory = AccountBackup::restore_archive_inventory(reader).await?;

    // Restore from archive whilst signed in (with provider),
    // overwrites existing data (backup)
    let signer = user.identity().signer().clone();
    let (mut provider, _) = new_local_provider(signer, None).await?;

    let options = RestoreOptions {
        selected: vaults.clone().into_iter().map(|v| v.0).collect(),
        passphrase: Some(passphrase.clone()),
        files_dir: Some(ExtractFilesLocation::Path(files_dir.clone())),
    };

    let reader = Cursor::new(&mut archive_buffer);
    let (targets, _) =
        AccountBackup::restore_archive_buffer(reader, options, true).await?;

    provider.restore_archive(&targets).await?;

    // Remove the account
    user.delete_account(&paths).await?;

    // Restore when not signed in - the account must not exist,
    // equivalent to importing an account
    let options = RestoreOptions {
        selected: vaults.into_iter().map(|v| v.0).collect(),
        passphrase: Some(passphrase),
        files_dir: Some(ExtractFilesLocation::Path(files_dir.to_owned())),
    };
    let reader = Cursor::new(&mut archive_buffer);
    AccountBackup::restore_archive_buffer(reader, options, false).await?;

    // Reset the cache dir so we don't interfere
    // with other tests
    AppPaths::clear_data_dir();

    Ok(())
}
