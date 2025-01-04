use anyhow::Result;
use sos_password::diceware::generate_passphrase;
use sos_sdk::{
    constants::LOGIN_SIGNING_KEY_URN,
    crypto::AccessKey,
    encode,
    identity::MemoryIdentityFolder,
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRow},
        BuilderCredentials, Gatekeeper, Vault, VaultBuilder, VaultFlags,
    },
    Error,
};
use urn::Urn;

#[tokio::test]
async fn identity_not_identity_vault() -> Result<()> {
    let (password, _) = generate_passphrase()?;
    let vault = VaultBuilder::new()
        .build(BuilderCredentials::Password(password.clone(), None))
        .await?;
    let buffer = encode(&vault).await?;

    let key: AccessKey = password.into();
    let result = MemoryIdentityFolder::login(buffer, &key).await;

    if let Err(sos_login::Error::NotIdentityFolder) = result {
        Ok(())
    } else {
        panic!("expecting identity vault error");
    }
}

#[tokio::test]
async fn no_signing_key() -> Result<()> {
    let (password, _) = generate_passphrase()?;

    let vault = VaultBuilder::new()
        .flags(VaultFlags::IDENTITY)
        .build(BuilderCredentials::Password(password.clone(), None))
        .await?;

    let buffer = encode(&vault).await?;

    let key: AccessKey = password.into();
    let result = MemoryIdentityFolder::login(buffer, &key).await;

    if let Err(sos_login::Error::NoSigningKey) = result {
        Ok(())
    } else {
        panic!("expecting no identity signer error");
    }
}

#[tokio::test]
async fn no_identity_key() -> Result<()> {
    let (password, _) = generate_passphrase()?;

    let vault = VaultBuilder::new()
        .flags(VaultFlags::IDENTITY)
        .build(BuilderCredentials::Password(password.clone(), None))
        .await?;

    let mut keeper = Gatekeeper::new(vault);
    let key = password.clone().into();
    keeper.unlock(&key).await?;

    // Create a secret using the expected name but of the wrong kind
    let signer_secret = Secret::Note {
        text: "Mock note".to_owned().into(),
        user_data: Default::default(),
    };

    let urn: Urn = LOGIN_SIGNING_KEY_URN.parse()?;
    let mut signer_meta =
        SecretMeta::new(urn.as_str().to_owned(), signer_secret.kind());
    signer_meta.set_urn(Some(urn));
    let secret_data =
        SecretRow::new(SecretId::new_v4(), signer_meta, signer_secret);
    keeper.create_secret(&secret_data).await?;

    let vault: Vault = keeper.into();
    let buffer = encode(&vault).await?;

    let key: AccessKey = password.into();
    let result = MemoryIdentityFolder::login(buffer, &key).await;

    if let Err(sos_login::Error::NoIdentityKey) = result {
        Ok(())
    } else {
        panic!("expecting identity signer kind error");
    }
}
