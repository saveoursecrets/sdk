use anyhow::Result;
use sos_backend::{AccessPoint, BackendTarget};
use sos_core::{crypto::AccessKey, encode, AccountId, Paths, VaultFlags};
use sos_login::IdentityFolder;
use sos_password::diceware::generate_passphrase;
use sos_vault::{BuilderCredentials, SecretAccess, Vault, VaultBuilder};
use sos_vfs as vfs;
use tempfile::tempdir_in;

#[tokio::test]
async fn identity_not_vault() -> Result<()> {
    let temp_dir = tempdir_in("target")?;
    let account_id = AccountId::random();
    let (password, _) = generate_passphrase()?;
    let vault = VaultBuilder::new()
        .build(BuilderCredentials::Password(password.clone(), None))
        .await?;
    let buffer = encode(&vault).await?;

    Paths::scaffold(&temp_dir.path().to_owned()).await?;
    let paths =
        Paths::new_client(temp_dir.path()).with_account_id(&account_id);
    vfs::write(paths.identity_vault(), &buffer).await?;
    let target = BackendTarget::from_paths(&paths).await?;

    let key: AccessKey = password.into();
    let result = IdentityFolder::login(&target, &account_id, &key).await;

    if let Err(sos_login::Error::NotIdentityFolder) = result {
        Ok(())
    } else {
        panic!("expecting identity vault error");
    }
}

#[tokio::test]
async fn identity_no_key() -> Result<()> {
    let temp_dir = tempdir_in("target")?;
    let account_id = AccountId::random();
    let (password, _) = generate_passphrase()?;

    let vault = VaultBuilder::new()
        .flags(VaultFlags::IDENTITY)
        .build(BuilderCredentials::Password(password.clone(), None))
        .await?;

    let mut keeper = AccessPoint::from_vault(vault);
    let key = password.clone().into();
    keeper.unlock(&key).await?;

    let vault: Vault = keeper.into();
    let buffer = encode(&vault).await?;

    Paths::scaffold(&temp_dir.path().to_owned()).await?;
    let paths =
        Paths::new_client(temp_dir.path()).with_account_id(&account_id);
    vfs::write(paths.identity_vault(), &buffer).await?;
    let target = BackendTarget::from_paths(&paths).await?;

    let key: AccessKey = password.into();
    let result = IdentityFolder::login(&target, &account_id, &key).await;

    if let Err(sos_login::Error::NoIdentityKey) = result {
        Ok(())
    } else {
        panic!("expecting identity signer kind error");
    }
}
