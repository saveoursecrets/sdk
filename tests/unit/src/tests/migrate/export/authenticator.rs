use anyhow::Result;
use secrecy::SecretString;
use sos_backend::AccessPoint;
use sos_core::{crypto::AccessKey, SecretId, VaultFlags};
use sos_migrate::{export_authenticator, import_authenticator};
use sos_password::diceware::generate_passphrase;
use sos_test_utils::mock;
use sos_vault::{
    secret::SecretRow, BuilderCredentials, SecretAccess, VaultBuilder,
};
use tempfile::NamedTempFile;

async fn create_mock_authenticator(
) -> Result<(AccessPoint, SecretString, SecretRow)> {
    let (folder_key, _) = generate_passphrase()?;
    let vault = VaultBuilder::new()
        .flags(VaultFlags::AUTHENTICATOR)
        .build(BuilderCredentials::Password(folder_key.clone(), None))
        .await?;

    let key: AccessKey = folder_key.clone().into();
    let mut keeper = AccessPoint::from_vault(vault);
    keeper.unlock(&key).await?;

    let (meta, secret) = mock::totp("mock@example.com");
    let secret_data = SecretRow::new(SecretId::new_v4(), meta, secret);
    keeper.create_secret(&secret_data).await?;
    Ok((keeper, folder_key, secret_data))
}

#[tokio::test]
async fn authenticator_export_import() -> Result<()> {
    let (auth, folder_password, secret_data) =
        create_mock_authenticator().await?;

    let archive = NamedTempFile::new()?;

    export_authenticator(archive.path(), &auth, true).await?;

    let vault = VaultBuilder::new()
        .flags(VaultFlags::AUTHENTICATOR)
        .build(BuilderCredentials::Password(folder_password.clone(), None))
        .await?;

    let key: AccessKey = folder_password.into();
    let mut keeper = AccessPoint::from_vault(vault);
    keeper.unlock(&key).await?;

    import_authenticator(archive.path(), &mut keeper).await?;

    assert_eq!(1, keeper.vault().len());

    let (meta, secret, _) =
        keeper.read_secret(secret_data.id()).await?.unwrap();

    assert_eq!(secret_data.meta().label(), meta.label());
    assert_eq!(secret_data.secret(), &secret);

    Ok(())
}
