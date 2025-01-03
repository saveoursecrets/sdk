use anyhow::Result;
use secrecy::ExposeSecret;
use sos_sdk::prelude::*;
use sos_test_utils::*;
use tempfile::NamedTempFile;

async fn mock_event_log_file(
) -> Result<(NamedTempFile, FolderEventLog, PrivateKey, SecretId)> {
    let (encryption_key, _, _) = mock_encryption_key()?;
    let (_, mut vault) = mock_vault_file().await?;

    let temp = NamedTempFile::new()?;
    let mut event_log = FolderEventLog::new(temp.path()).await?;

    // Create the vault
    let event = vault.into_event().await?;
    event_log.apply(vec![&event]).await?;

    // Create a secret
    let (secret_id, _, _, _, event) =
        mock_vault_note(&mut vault, &encryption_key, "foo", "bar").await?;
    event_log.apply(vec![&event]).await?;

    // Update the secret
    let (_, _, _, event) = mock_vault_note_update(
        &mut vault,
        &encryption_key,
        &secret_id,
        "bar",
        "qux",
    )
    .await?;
    if let Some(event) = event {
        event_log.apply(vec![&event]).await?;
    }

    // Create another secret
    let (del_id, _, _, _, event) =
        mock_vault_note(&mut vault, &encryption_key, "qux", "baz").await?;
    event_log.apply(vec![&event]).await?;

    let event = vault.delete_secret(&del_id).await?;
    if let Some(event) = event {
        event_log.apply(vec![&event]).await?;
    }

    Ok((temp, event_log, encryption_key, secret_id))
}

#[tokio::test]
async fn event_log_reduce_build() -> Result<()> {
    let (temp, event_log, encryption_key, secret_id) =
        mock_event_log_file().await?;

    assert_eq!(5, event_log.tree().len());

    let vault = FolderReducer::new()
        .reduce(&event_log)
        .await?
        .build(true)
        .await?;

    assert_eq!(1, vault.len());

    let entry = vault.get(&secret_id);
    assert!(entry.is_some());

    if let Some(VaultCommit(_, VaultEntry(meta_aead, secret_aead))) = entry {
        let meta = vault.decrypt(&encryption_key, meta_aead).await?;
        let secret = vault.decrypt(&encryption_key, secret_aead).await?;
        let meta: SecretMeta = decode(&meta).await?;
        let secret: Secret = decode(&secret).await?;

        assert_eq!("bar", meta.label());
        assert_eq!("qux", {
            match &secret {
                Secret::Note { text, .. } => text.expose_secret(),
                _ => panic!("unexpected secret type"),
            }
        });
    }

    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn event_log_reduce_compact() -> Result<()> {
    let (_temp, event_log, _encryption_key, _secret_id) =
        mock_event_log_file().await?;

    assert_eq!(5, event_log.tree().len());

    // Get a vault so we can assert on the compaction result
    let vault = FolderReducer::new()
        .reduce(&event_log)
        .await?
        .build(true)
        .await?;

    // Get the compacted series of events
    let events = FolderReducer::new()
        .reduce(&event_log)
        .await?
        .compact()
        .await?;

    assert_eq!(2, events.len());

    let compact_temp = NamedTempFile::new()?;
    let mut compact = FolderEventLog::new(compact_temp.path()).await?;
    for event in events {
        compact.apply(vec![&event]).await?;
    }

    let compact_vault = FolderReducer::new()
        .reduce(&compact)
        .await?
        .build(true)
        .await?;
    assert_eq!(vault, compact_vault);

    Ok(())
}
