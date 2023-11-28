use anyhow::Result;
use sos_net::sdk::{
    account::{AccountsList, LocalAccount, UserPaths},
    passwd::diceware::generate_passphrase,
};

use crate::test_utils::{setup, teardown};

const TEST_ID: &str = "account_lifecycle";

/// Tests the basic account lifecycle. Account creation, sign in
/// and sign out followed by account deletion.
#[tokio::test]
async fn integration_account_lifecycle() -> Result<()> {
    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (passphrase, _) = generate_passphrase()?;

    UserPaths::scaffold(Some(data_dir.clone())).await?;
    let paths = UserPaths::new_global(data_dir.clone());
    let accounts = AccountsList::list_accounts(Some(&paths)).await?;
    assert_eq!(0, accounts.len());

    let (mut account, _new_account) = LocalAccount::new_account(
        account_name.clone(),
        passphrase.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let accounts = AccountsList::list_accounts(Some(&paths)).await?;
    assert_eq!(1, accounts.len());

    account.sign_in(passphrase.clone()).await?;
    assert!(account.is_authenticated());

    let folders = account.list_folders().await?;
    assert_eq!(3, folders.len());

    account.rename_account("account_name".to_string()).await?;
    let data = account.account_data().await?;
    assert_eq!("account_name", data.account.label());

    account.sign_out().await?;
    assert!(!account.is_authenticated());

    // Must sign in again to delete the account
    account.sign_in(passphrase.clone()).await?;
    account.delete_account().await?;

    // Deleting the account is an automatic sign out
    assert!(!account.is_authenticated());

    teardown(TEST_ID).await;

    Ok(())
}
