use anyhow::Result;

use std::{io::Cursor, path::PathBuf, sync::Arc};

use sos_net::sdk::{
    account::{
        archive::{AccountBackup, ExtractFilesLocation, RestoreOptions},
        files::FileStorage,
        search::SearchIndex,
        Account, AccountsList, FolderStorage,
        LocalAccount,
    },
    hex,
    passwd::diceware::generate_passphrase,
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

    let account_name = TEST_ID.to_string();
    let (passphrase, _) = generate_passphrase()?;

    let (mut account, new_account) = Account::<()>::new_account(
        account_name.clone(),
        passphrase.clone(),
        Some(test_data_dir.clone()),
        None,
    )
    .await?;

    account.sign_in(passphrase.clone()).await?;

    account
        .rename_account("New account name".to_string())
        .await?;

    let paths = account.paths().clone();
    let local_accounts = AccountsList::new(&paths);
    let accounts = AccountsList::list_accounts(Some(&paths)).await?;
    assert_eq!(1, accounts.len());
    let user = account.user()?;

    let address = new_account.address.clone();
    let summary = new_account.default_folder().clone();

    {
        let keeper = user.identity().keeper();
        let reader = keeper.read().await;
        assert_eq!("New account name", reader.vault().name());
    }

    let vaults = local_accounts.list_local_vaults(false).await?;
    // Default, Contacts and Archive vaults
    assert_eq!(3, vaults.len());

    /*
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
    */

    // Make sure we can find a vault passphrase and unlock it
    let default_vault_passphrase =
        LocalAccount::find_folder_password(
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

    //let file_passphrase =
        //LocalAccount::find_file_encryption_password(
            //user.identity().keeper(),
        //)
        //.await?;
    let source_file = PathBuf::from("tests/fixtures/test-file.txt");
    
    let files_dir = paths.files_dir();

    /*
    // Encrypt
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
    */

    //let expected = vfs::read(source_file).await?;
    //assert_eq!(expected, buffer);

    let mut archive_buffer =
        AccountBackup::export_archive_buffer(&address, &paths).await?;
    let reader = Cursor::new(&mut archive_buffer);
    let _inventory = AccountBackup::restore_archive_inventory(reader).await?;

    // Restore from archive whilst signed in (with provider),
    // overwrites existing data (backup)
    let signer = user.identity().signer().clone();
    let mut provider = FolderStorage::new(
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
