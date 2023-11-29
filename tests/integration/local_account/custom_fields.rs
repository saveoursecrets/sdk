use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::{
    account::{LocalAccount, UserPaths},
    passwd::diceware::generate_passphrase,
    vault::secret::{SecretId, SecretRow}
};

const TEST_ID: &str = "custom_fields";

/// Tests modifiying custom fields. Custom fields are 
/// nested secrets included in a secret's user data.
#[tokio::test]
async fn integration_custom_fields() -> Result<()> {
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
    let address = account.address().clone();

    let default_folder = new_account.default_folder();

    account.sign_in(password.clone()).await?;
    let folders = account.list_folders().await?;
    account.open_folder(&default_folder).await?;

    // Create secret
    let (meta, secret) = mock::note("note", TEST_ID);
    let (id, _, _, folder) = account
        .create_secret(meta, secret, Default::default())
        .await?;
    assert_eq!(default_folder, &folder);

    // Read secret
    let (mut data, _) = account.read_secret(&id, Default::default()).await?;
    assert_eq!(&id, data.id());
    assert_eq!("note", data.meta().label());

    // Create a secret to add as a custom field
    let (field_meta, field_secret) =
        mock::password("password_field", generate_passphrase()?.0);
    
    // Add the custom field
    let mut user_data = data.secret_mut().user_data_mut();
    user_data.push(
        SecretRow::new(
            SecretId::new_v4(), field_meta, field_secret));
    
    /*
    account
        .update_secret(
            &data.id,
            data.meta.clone(),
            Some(data.secret),
            Default::default(),
            None,
        )
        .await?;
    */

    teardown(TEST_ID).await;

    Ok(())
}
