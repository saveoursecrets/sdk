use crate::test_utils::{mock_note, setup, teardown};
use anyhow::Result;
use sos_net::sdk::{
    account::{LocalAccount, UserPaths},
    passwd::diceware::generate_passphrase,
    vfs,
};

const TEST_ID: &str = "folder_lifecycle";

/// Tests the basic folder lifecycle; create, write, export,
/// import and delete.
#[tokio::test]
async fn integration_folder_lifecycle() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    UserPaths::scaffold(Some(data_dir.clone())).await?;
    UserPaths::new_global(data_dir.clone());

    let (mut account, new_account) = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let default_folder = new_account.default_folder();
    account.sign_in(password.clone()).await?;
    account.open_folder(&default_folder).await?;

    // Create a folder
    let folder_name = "folder_name";
    let (folder, _, _, _) =
        account.create_folder(folder_name.to_string()).await?;

    // Open the new folder for writing
    account.open_folder(&folder).await?;

    // Create a secret in the new folder
    let (meta, secret) = mock_note("note", TEST_ID);
    let (id, _, _, secret_folder) = account
        .create_secret(meta, secret, Default::default())
        .await?;
    assert_eq!(&folder, &secret_folder);

    // Switch to the default folder for writing
    account.open_folder(&default_folder).await?;

    // Now read using the specific folder
    let (data, _) = account.read_secret(&id, Some(folder.clone())).await?;
    assert_eq!(Some(id), data.id);
    assert_eq!("note", data.meta.label());

    // Changed the currently open folder by reading
    // from an explicit folder
    let current_folder = {
        let storage = account.storage()?;
        let reader = storage.read().await;
        reader.current_folder().cloned()
    };
    assert_eq!(Some(&folder), current_folder.as_ref());

    // Export the folder and save the password for the exported
    // folder in the default folder
    let (folder_password, _) = generate_passphrase()?;
    let exported = data_dir.join("exported.vault");
    account
        .export_folder(
            &exported,
            &folder,
            folder_password.clone().into(),
            true,
        )
        .await?;
    assert!(vfs::try_exists(&exported).await?);

    // Now delete the folder
    account.delete_folder(&folder).await?;
    assert!(account.find(|f| f.id() == folder.id()).await.is_none());

    // Import the folder we exported
    account
        .import_folder(&exported, folder_password.into(), false)
        .await?;
    assert!(account.find(|f| f.id() == folder.id()).await.is_some());

    // Check we can read the secret data
    let (data, _) = account.read_secret(&id, Some(folder.clone())).await?;
    assert_eq!(Some(id), data.id);
    assert_eq!("note", data.meta.label());

    teardown(TEST_ID).await;

    Ok(())
}
