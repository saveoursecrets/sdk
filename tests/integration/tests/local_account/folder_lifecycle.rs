use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_account::{Account, FolderCreate, LocalAccount, SecretChange};
use sos_client_storage::NewFolderOptions;
use sos_sdk::prelude::*;
use sos_test_utils::make_client_backend;

/// Tests the basic folder lifecycle; create, write, export,
/// import and delete.
#[tokio::test]
async fn local_folder_lifecycle() -> Result<()> {
    const TEST_ID: &str = "folder_lifecycle";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_global(&data_dir);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        make_client_backend(&paths).await?,
    )
    .await?;

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;
    let default_folder = account.default_folder().await.unwrap();

    // Create a folder
    let folder_name = "folder_name";
    let FolderCreate { folder, .. } = account
        .create_folder(NewFolderOptions::new(folder_name.to_owned()))
        .await?;

    // Open the new folder for writing
    account.open_folder(folder.id()).await?;

    // Create a secret in the new folder
    let (meta, secret) = mock::note("note", TEST_ID);
    let SecretChange {
        id,
        folder: secret_folder,
        ..
    } = account
        .create_secret(meta, secret, Default::default())
        .await?;
    assert_eq!(&folder, &secret_folder);

    // Switch to the default folder for writing
    account.open_folder(default_folder.id()).await?;

    // Now read using the specific folder
    let (data, _) = account.read_secret(&id, Some(folder.id())).await?;
    assert_eq!(&id, data.id());
    assert_eq!("note", data.meta().label());

    // Export the folder and save the password for the exported
    // folder in the default folder
    let (folder_password, _) = generate_passphrase()?;
    let exported = data_dir.join("exported.vault");
    account
        .export_folder(
            &exported,
            folder.id(),
            folder_password.clone().into(),
            true,
        )
        .await?;
    assert!(vfs::try_exists(&exported).await?);

    // Rename a folder
    let folder_name = "new_name";
    account
        .rename_folder(default_folder.id(), folder_name.to_string())
        .await?;
    let default_folder = account.default_folder().await.unwrap();
    assert_eq!(folder_name, default_folder.name());

    // Now delete the folder
    account.delete_folder(folder.id()).await?;
    assert!(account.find(|f| f.id() == folder.id()).await.is_none());

    // Import the folder we exported
    let FolderCreate {
        folder: imported_folder,
        ..
    } = account
        .import_folder(&exported, folder_password.into(), false)
        .await?;
    assert!(account.find(|f| f.id() == folder.id()).await.is_some());

    // Check we can read the secret data
    let (data, _) =
        account.read_secret(&id, Some(imported_folder.id())).await?;
    assert_eq!(&id, data.id());
    assert_eq!("note", data.meta().label());

    teardown(TEST_ID).await;

    Ok(())
}
