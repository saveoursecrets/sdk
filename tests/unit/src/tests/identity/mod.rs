use anyhow::Result;
use sos_backend::BackendGateKeeper;
use sos_core::AccountId;
use sos_core::{crypto::AccessKey, encode};
use sos_login::DiscIdentityFolder;
use sos_password::diceware::generate_passphrase;
use sos_vault::{
    BuilderCredentials, Keeper, Vault, VaultBuilder, VaultFlags,
};
use sos_vfs as vfs;
use tempfile::NamedTempFile;

#[tokio::test]
async fn identity_not_identity_vault() -> Result<()> {
    let account_id = AccountId::random();
    let (password, _) = generate_passphrase()?;
    let vault = VaultBuilder::new()
        .build(BuilderCredentials::Password(password.clone(), None))
        .await?;
    let buffer = encode(&vault).await?;
    let file = NamedTempFile::new()?;
    vfs::write(file.path(), &buffer).await?;

    let key: AccessKey = password.into();
    let result =
        DiscIdentityFolder::login(&account_id, file.path(), &key).await;

    if let Err(sos_login::Error::NotIdentityFolder) = result {
        Ok(())
    } else {
        panic!("expecting identity vault error");
    }
}

#[tokio::test]
async fn no_identity_key() -> Result<()> {
    let account_id = AccountId::random();
    let (password, _) = generate_passphrase()?;

    let vault = VaultBuilder::new()
        .flags(VaultFlags::IDENTITY)
        .build(BuilderCredentials::Password(password.clone(), None))
        .await?;

    let mut keeper = BackendGateKeeper::new_vault(vault);
    let key = password.clone().into();
    keeper.unlock(&key).await?;

    let vault: Vault = keeper.into();
    let buffer = encode(&vault).await?;
    let file = NamedTempFile::new()?;
    vfs::write(file.path(), &buffer).await?;

    let key: AccessKey = password.into();
    let result =
        DiscIdentityFolder::login(&account_id, file.path(), &key).await;

    if let Err(sos_login::Error::NoIdentityKey) = result {
        Ok(())
    } else {
        panic!("expecting identity signer kind error");
    }
}
