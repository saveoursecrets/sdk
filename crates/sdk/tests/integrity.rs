use anyhow::Result;
use futures::{pin_mut, StreamExt};
use sos_sdk::prelude::*;
use sos_test_utils::*;
use std::io::Write;
use tempfile::NamedTempFile;

// TODO: test for corrupt event log
#[tokio::test]
async fn integrity_events() -> Result<()> {
    let (temp, _, _) = mock_event_log_file().await?;
    let stream = event_integrity(temp.path());
    pin_mut!(stream);

    assert!(stream.next().await.unwrap()?.is_ok());
    assert!(stream.next().await.unwrap()?.is_ok());
    assert!(stream.next().await.unwrap()?.is_ok());
    assert!(stream.next().await.is_none());

    Ok(())
}

// TODO: test for corrupt vault
#[tokio::test]
async fn integrity_empty_vault() -> Result<()> {
    let (temp, _) = mock_vault_file().await?;
    let stream = vault_integrity(temp.path());
    pin_mut!(stream);
    assert!(stream.next().await.is_none());
    Ok(())
}

#[tokio::test]
async fn integrity_vault() -> Result<()> {
    let (encryption_key, _, _) = mock_encryption_key()?;
    let (_, mut vault) = mock_vault_file().await?;
    let secret_label = "Test note";
    let secret_note = "Super secret note for you to read.";
    let (_secret_id, _commit, _, _, _) = mock_vault_note(
        &mut vault,
        &encryption_key,
        secret_label,
        secret_note,
    )
    .await?;

    let buffer = encode(&vault).await?;
    let mut temp = NamedTempFile::new()?;
    temp.write_all(&buffer)?;

    let stream = vault_integrity(temp.path());
    pin_mut!(stream);

    let record = stream.next().await.unwrap()?;
    assert!(record.is_ok());
    assert!(stream.next().await.is_none());

    Ok(())
}
