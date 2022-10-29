use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use secrecy::ExposeSecret;
use sos_check::{keys, status, verify_vault, verify_wal};
use sos_core::{
    constants::{LOCAL_DIR, VAULTS_DIR},
    vault::Vault,
    wal::file::WalFile,
};
use sos_node::client::{
    account::AccountCredentials, provider::StorageProvider,
};

#[tokio::test]
#[serial]
async fn integration_check_integrity() -> Result<()> {
    let dirs = setup(1)?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let (address, credentials, mut node_cache, _signer) =
        signup(&dirs, 0).await?;
    let AccountCredentials {
        summary,
        encryption_passphrase,
        ..
    } = credentials;

    // Use the new vault
    node_cache.open_vault(&summary, encryption_passphrase.expose_secret())?;

    // Create some secrets
    let _notes = create_secrets(&mut node_cache, &summary).await?;

    let expected_dir = dirs.clients.get(0).unwrap();

    // Local vault file
    let expected_vault = expected_dir
        .join(LOCAL_DIR)
        .join(address.to_string())
        .join(VAULTS_DIR)
        .join(format!("{}.{}", summary.id(), Vault::extension()));

    // WAL for the local data
    let expected_wal = expected_dir
        .join(LOCAL_DIR)
        .join(address.to_string())
        .join(VAULTS_DIR)
        .join(format!("{}.{}", summary.id(), WalFile::extension()));

    assert!(expected_vault.exists());
    assert!(expected_wal.exists());
    assert!(keys(expected_vault.clone()).is_ok());
    assert!(status(expected_vault.clone()).is_ok());
    assert!(verify_vault(expected_vault.clone(), true, true).is_ok());
    assert!(verify_wal(expected_wal.clone(), true, true).is_ok());

    // Close the vault
    node_cache.close_vault();

    Ok(())
}
