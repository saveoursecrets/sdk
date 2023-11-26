use anyhow::Result;

use std::{io::Cursor, path::PathBuf, sync::Arc};

use sos_net::sdk::{
    account::{
        AccountBackup, AccountBuilder, DelegatedPassphrase,
        ExtractFilesLocation, FileStorage, CreatedAccount, LocalAccounts,
        LocalProvider, Login, NewAccount, RestoreOptions, UserPaths,
    },
    constants::{LOGIN_AGE_KEY_URN, LOGIN_SIGNING_KEY_URN},
    hex,
    passwd::diceware::generate_passphrase,
    search::SearchIndex,
    urn::Urn,
    vault::{secret::SecretId, Gatekeeper, VaultId},
    vfs,
};
use tokio::sync::RwLock;

use crate::test_utils::{setup, teardown};

const TEST_ID: &str = "account_manager";

#[tokio::test]
async fn integration_account_manager() -> Result<()> {
    let mut dirs = setup(TEST_ID, 1).await?;
    let test_data_dir = dirs.clients.remove(0);

    let account_name = "Mock account name".to_string();
    let folder_name = Some("Default folder".to_string());
    let (passphrase, _) = generate_passphrase()?;

    let new_account = AccountBuilder::new(
        account_name.clone(),
        passphrase.clone(),
        Some(test_data_dir.clone()),
    )
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
    let mut provider = LocalProvider::new(
        signer.address()?.to_string(),
        Some(test_data_dir.clone()),
    )
    .await?;

    let (imported_account, _) =
        provider.import_new_account(&new_account).await?;

    let NewAccount { address, .. } = new_account;
    let CreatedAccount { summary, .. } = imported_account;

    let paths = UserPaths::new(test_data_dir.clone(), &address.to_string());
    let local_accounts = LocalAccounts::new(&paths);
    let accounts = LocalAccounts::list_accounts(Some(&paths)).await?;
    assert_eq!(1, accounts.len());

    let identity_index = Arc::new(RwLock::new(SearchIndex::new()));
    let mut user = Login::sign_in(
        &address,
        &paths,
        passphrase.clone(),
        Arc::clone(&identity_index),
    )
    .await?;

    user.rename_account(&paths, "New account name".to_string())
        .await?;
    {
        let keeper = user.identity().keeper();
        let reader = keeper.read().await;
        assert_eq!("New account name", reader.vault().name());
    }

    let vaults = local_accounts.list_local_vaults(false).await?;
    // Default, Contacts, Authenticator and Archive vaults
    assert_eq!(4, vaults.len());

    let identity_reader = identity_index.read().await;

    // Check we can find the signing key
    let signing_urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
    {
        let keeper = user.identity().keeper();
        let reader = keeper.read().await;
        let signing_key =
            identity_reader.find_by_urn(reader.id(), &signing_urn);
        assert!(signing_key.is_some());
    }

    // Check AGE key
    let age_urn: Urn = LOGIN_AGE_KEY_URN.parse()?;
    {
        let keeper = user.identity().keeper();
        let reader = keeper.read().await;
        let age_key = identity_reader.find_by_urn(reader.id(), &age_urn);
        assert!(age_key.is_some());
    }

    // Make sure we can find a vault passphrase and unlock it
    let default_vault_passphrase =
        DelegatedPassphrase::find_vault_passphrase(
            user.identity().keeper(),
            summary.id(),
        )
        .await?;

    let default_index = Arc::new(RwLock::new(SearchIndex::new()));
    let (default_vault, _) =
        local_accounts.find_local_vault(summary.id(), false).await?;
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
    let mut provider = LocalProvider::new(
        signer.address()?.to_string(),
        Some(test_data_dir.clone()),
    )
    .await?;

    let options = RestoreOptions {
        selected: vaults.clone().into_iter().map(|v| v.0).collect(),
        passphrase: Some(passphrase.clone()),
        files_dir: Some(ExtractFilesLocation::Path(files_dir.clone())),
    };

    let reader = Cursor::new(&mut archive_buffer);
    let (targets, _) = AccountBackup::restore_archive_buffer(
        reader,
        options,
        true,
        Some(test_data_dir.clone()),
    )
    .await?;

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
    AccountBackup::restore_archive_buffer(
        reader,
        options,
        false,
        Some(test_data_dir),
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
