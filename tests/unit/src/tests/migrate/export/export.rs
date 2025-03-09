use anyhow::Result;
use sos_backend::AccessPoint;
use sos_core::{crypto::AccessKey, SecretId, VaultFlags};
use sos_migrate::export::PublicExport;
use sos_password::diceware::generate_passphrase;
use sos_test_utils::mock;
use sos_vault::{
    secret::SecretRow, BuilderCredentials, SecretAccess, VaultBuilder,
};
use std::io::Cursor;
use tokio::io::{AsyncSeek, AsyncWrite};

async fn create_mock_migration<W: AsyncWrite + AsyncSeek + Unpin>(
    writer: W,
) -> Result<PublicExport<W>> {
    let (passphrase, _) = generate_passphrase()?;

    let vault = VaultBuilder::new()
        .flags(VaultFlags::DEFAULT)
        .build(BuilderCredentials::Password(passphrase.clone(), None))
        .await?;

    let key: AccessKey = passphrase.into();
    let mut migration = PublicExport::new(writer);
    let mut keeper = AccessPoint::from_vault(vault);
    keeper.unlock(&key).await?;

    let (meta, secret, _, _) =
        mock::secret_note("Mock note", "Value for the mock note").await?;
    let secret_data = SecretRow::new(SecretId::new_v4(), meta, secret);
    keeper.create_secret(&secret_data).await?;

    let (meta, secret, _, _) = mock::secret_file(
        "Mock file",
        "test.txt",
        "text/plain",
        "Test value".as_bytes().to_vec(),
    )
    .await?;
    let secret_data = SecretRow::new(SecretId::new_v4(), meta, secret);
    keeper.create_secret(&secret_data).await?;

    migration.add(&keeper).await?;
    Ok(migration)
}

#[tokio::test]
async fn migration_public_archive() -> Result<()> {
    let mut archive = Vec::new();
    let migration = create_mock_migration(Cursor::new(&mut archive)).await?;
    let _ = migration.finish().await?;
    Ok(())
}
