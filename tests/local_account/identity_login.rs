use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::sdk::{prelude::*, vfs};

/// Tests creating an identity vault and logging in
/// with the new vault and managing delegated passwords.
#[tokio::test]
async fn local_identity_login() -> Result<()> {
    const TEST_ID: &str = "identity_login";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    Paths::scaffold(Some(data_dir.clone())).await?;
    Paths::new_global(data_dir.clone());

    let path = data_dir.join("login.vault");
    let identity_vault = IdentityFolder::new(
        account_name,
        password.clone(),
        Some(data_dir.clone()),
    )
    .await?;

    let address = identity_vault.address().clone();
    let vault: Vault = identity_vault.into();

    let buffer = encode(&vault).await?;
    vfs::write(&path, buffer).await?;

    let paths = Paths::new(data_dir, address.to_string());
    paths.ensure().await?;
    let mut identity = Identity::new(paths);

    let key: AccessKey = password.into();
    identity.login(&path, &key).await?;

    let folder = VaultId::new_v4();
    let access_key: AccessKey = identity.generate_folder_password()?.into();
    identity
        .save_folder_password(&folder, access_key.clone())
        .await?;

    // Should be able to find the password we saved
    assert!(identity.find_folder_password(&folder).await.is_ok());

    identity.sign_out().await?;

    // Login again and check the secure access keys
    // are loaded at login
    identity.login(&path, &key).await?;

    // Remove the folder password
    identity.remove_folder_password(&folder).await?;

    teardown(TEST_ID).await;

    Ok(())
}
