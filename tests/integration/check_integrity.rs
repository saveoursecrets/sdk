use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use sos_check::{keys, status, verify_vault, verify_wal};
use sos_core::{vault::Vault, wal::file::WalFile};
use sos_node::client::{account::AccountCredentials, ClientCache};

#[tokio::test]
#[serial]
async fn integration_check_integrity() -> Result<()> {
    let dirs = setup(1)?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let (address, credentials, mut file_cache) = signup(&dirs, 0).await?;
    let AccountCredentials {
        summary,
        encryption_passphrase,
        ..
    } = credentials;

    // Use the new vault
    file_cache
        .open_vault(&summary, &encryption_passphrase)
        .await?;

    // Create some secrets
    let _notes = create_secrets(&mut file_cache, &summary).await?;

    let expected_dir = dirs.clients.get(0).unwrap().join(address.to_string());
    let expected_vault =
        expected_dir.join(format!("{}.{}", summary.id(), Vault::extension()));
    let expected_wal = expected_dir.join(format!(
        "{}.{}",
        summary.id(),
        WalFile::extension()
    ));

    assert!(expected_vault.exists());
    assert!(expected_wal.exists());
    assert!(keys(expected_vault.clone()).is_ok());
    assert!(status(expected_vault.clone()).is_ok());
    assert!(verify_vault(expected_vault.clone(), true, true).is_ok());
    assert!(verify_wal(expected_wal.clone(), true, true).is_ok());

    // Close the vault
    file_cache.close_vault();

    Ok(())
}
