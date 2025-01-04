use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_account::{Account, FolderCreate, LocalAccount};
use sos_sdk::prelude::*;

/// Tests sign in when a folder password is missing.
#[tokio::test]
async fn sign_in_no_folder_password() -> Result<()> {
    const TEST_ID: &str = "no_folder_password";
    // crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
    )
    .await?;

    let key: AccessKey = password.clone().into();
    account.sign_in(&key).await?;

    // Create folder
    let FolderCreate { folder, .. } = account
        .create_folder(TEST_ID.to_owned(), Default::default())
        .await?;

    // Remove the folder password
    account
        .user_mut()?
        .remove_folder_password(folder.id())
        .await?;

    account.sign_out().await?;

    // Should be able to sign in when the folder password
    // is missing so that we can still access other folders
    // that can be unlocked
    account.sign_in(&key).await?;

    account.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}
