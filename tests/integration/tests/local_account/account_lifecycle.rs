use anyhow::Result;
use sos_account::{Account, LocalAccount};
use sos_sdk::prelude::*;

use crate::test_utils::{setup, teardown};

/// Tests the basic account lifecycle. Account creation, sign in
/// and sign out followed by account deletion.
#[tokio::test]
async fn local_account_lifecycle() -> Result<()> {
    const TEST_ID: &str = "account_lifecycle";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (passphrase, _) = generate_passphrase()?;

    Paths::scaffold(Some(data_dir.clone())).await?;
    let paths = Paths::new_global(data_dir.clone());
    let accounts = sos_vault::list_accounts(Some(&paths)).await?;
    assert_eq!(0, accounts.len());

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        passphrase.clone(),
        Some(data_dir.clone()),
    )
    .await?;

    let accounts = sos_vault::list_accounts(Some(&paths)).await?;
    assert_eq!(1, accounts.len());

    let key: AccessKey = passphrase.into();
    account.sign_in(&key).await?;
    assert!(account.is_authenticated().await);

    let folders = account.list_folders().await?;
    assert_eq!(1, folders.len());

    account.rename_account("account_name".to_string()).await?;
    let data = account.account_data().await?;
    assert_eq!("account_name", data.account.label());

    account.sign_out().await?;
    assert!(!account.is_authenticated().await);

    // Must sign in again to delete the account
    account.sign_in(&key).await?;

    account.delete_account().await?;

    // Deleting the account is an automatic sign out
    assert!(!account.is_authenticated().await);

    teardown(TEST_ID).await;

    Ok(())
}
