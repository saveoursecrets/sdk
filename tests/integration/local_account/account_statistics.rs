use anyhow::Result;
use sos_net::sdk::{
    account::{LocalAccount, UserPaths},
    passwd::diceware::generate_passphrase,
    vault::secret::SecretType,
};

use crate::test_utils::{setup, teardown, mock_note, mock_login};

const TEST_ID: &str = "account_statistics";

/// Tests the account statistics.
#[tokio::test]
async fn integration_account_statistics() -> Result<()> {
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
    account.list_folders().await?;
    account.open_folder(&default_folder).await?;

    let statistics = account.statistics().await;
    assert_eq!(0, statistics.documents);
    assert!(statistics.folders.is_empty());
    assert!(statistics.tags.is_empty());
    assert!(statistics.types.is_empty());
    assert_eq!(0, statistics.favorites);

    // Create a note
    let (meta, secret) = mock_note("note", TEST_ID);
    let (id, _, _, _) = account
        .create_secret(meta, secret, Default::default())
        .await?;

    let statistics = account.statistics().await;
    assert_eq!(1, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 1)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::Note));

    // Create a login
    let (login_password, _) = generate_passphrase()?;
    let (meta, secret) = mock_login("login", TEST_ID, login_password);
    let (id, _, _, _) = account
        .create_secret(meta, secret, Default::default())
        .await?;

    let statistics = account.statistics().await;
    assert_eq!(2, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 2)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::Account));


    //let statistics = account.statistics().await;
    //println!("{:#?}", statistics);

    teardown(TEST_ID).await;

    Ok(())
}
