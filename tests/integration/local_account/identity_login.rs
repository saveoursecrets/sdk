use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::{
    account::{Identity, LocalAccount, UserPaths},
    encode,
    passwd::diceware::generate_passphrase,
    vfs,
};

const TEST_ID: &str = "identity_login";

/// Tests creating an identity vault and logging in
/// with the new vault.
#[tokio::test]
async fn integration_identity_login() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    UserPaths::scaffold(Some(data_dir.clone())).await?;
    UserPaths::new_global(data_dir.clone());

    let path = data_dir.join("login.vault");
    let (address, vault) =
        Identity::new_login_vault("Login".to_owned(), password.clone())
            .await?;
    let buffer = encode(&vault).await?;
    vfs::write(&path, buffer).await?;

    let paths = UserPaths::new(data_dir, address.to_string());
    paths.ensure().await?;
    let mut identity = Identity::new(paths);

    identity.login(path, password).await?;

    teardown(TEST_ID).await;

    Ok(())
}
