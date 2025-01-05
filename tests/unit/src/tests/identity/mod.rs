use anyhow::Result;
use sos_core::AccountId;
use sos_password::diceware::generate_passphrase;
use sos_sdk::{
    crypto::AccessKey,
    encode,
    identity::MemoryIdentityFolder,
    vault::{
        BuilderCredentials, Gatekeeper, Vault, VaultBuilder, VaultFlags,
    },
};

#[tokio::test]
async fn identity_not_identity_vault() -> Result<()> {
    let account_id = AccountId::random();
    let (password, _) = generate_passphrase()?;
    let vault = VaultBuilder::new()
        .build(BuilderCredentials::Password(password.clone(), None))
        .await?;
    let buffer = encode(&vault).await?;

    let key: AccessKey = password.into();
    let result = MemoryIdentityFolder::login(&account_id, buffer, &key).await;

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

    let mut keeper = Gatekeeper::new(vault);
    let key = password.clone().into();
    keeper.unlock(&key).await?;

    let vault: Vault = keeper.into();
    let buffer = encode(&vault).await?;

    let key: AccessKey = password.into();
    let result = MemoryIdentityFolder::login(&account_id, buffer, &key).await;

    if let Err(sos_login::Error::NoIdentityKey) = result {
        Ok(())
    } else {
        panic!("expecting identity signer kind error");
    }
}
