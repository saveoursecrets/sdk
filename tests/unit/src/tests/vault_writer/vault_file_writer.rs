use super::create_secure_note;
use anyhow::Result;
use sos_filesystem::{Error, VaultFileWriter};
use sos_sdk::prelude::*;
use sos_test_utils::mock;

/// Test file writer deletion and splice logic.
#[tokio::test]
async fn vault_file_del_splice() -> Result<()> {
    let (encryption_key, _, _) = mock::encryption_key()?;
    let (temp, vault, _) = mock::vault_file().await?;

    let mut vault_access = VaultFileWriter::<Error>::new(temp.path()).await?;

    let secrets = [
        ("Note one", "First note"),
        ("Note two", "Second note"),
        ("Note three", "Third note"),
    ];

    let mut secret_ids = Vec::new();
    for note_data in secrets {
        let secret_id = create_secure_note(
            &mut vault_access,
            &vault,
            &encryption_key,
            note_data.0,
            note_data.1,
        )
        .await?;
        secret_ids.push(secret_id);
    }

    let del_secret_id = secret_ids.get(1).unwrap();
    let _ = vault_access.delete_secret(del_secret_id).await?;

    // Check the file identity is good after the deletion splice
    assert!(Header::read_header_file(temp.path()).await.is_ok());

    // Clean up other secrets
    for secret_id in secret_ids {
        let _ = vault_access.delete_secret(&secret_id).await?;
    }

    // Verify again to finish up
    assert!(Header::read_header_file(temp.path()).await.is_ok());

    temp.close()?;

    Ok(())
}
