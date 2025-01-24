use anyhow::Result;
use futures::{pin_mut, StreamExt};
use secrecy::ExposeSecret;
use sos_backend::{Folder, FolderEventLog};
use sos_core::{
    crypto::AccessKey, encode, events::EventLog, SecretId, VaultFlags,
};
use sos_test_utils::mock::{
    self, file_database, insert_database_vault, vault_file, vault_memory,
};
use sos_vault::secret::{Secret, SecretRow};
use sos_vfs as vfs;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::test]
async fn fs_folder_lifecycle() -> Result<()> {
    let (temp, vault, password) = vault_file().await?;
    let buffer = encode(&vault).await?;
    vfs::write(temp.path(), &buffer).await?;

    let mut folder = Folder::new_fs(temp.path()).await?;
    let key: AccessKey = password.into();
    assert_folder(&mut folder, key).await?;

    temp.close()?;
    Ok(())
}

#[tokio::test]
async fn db_folder_lifecycle() -> Result<()> {
    let (vault, password) = vault_memory().await?;
    let (temp, mut client) = file_database().await?;
    let (account_id, _, _) =
        insert_database_vault(&mut client, &vault, false).await?;

    let buffer = encode(&vault).await?;
    vfs::write(temp.path(), &buffer).await?;

    let mut folder =
        Folder::new_db(client.clone(), account_id, *vault.id()).await?;
    let key: AccessKey = password.into();
    assert_folder(&mut folder, key).await?;

    client.close().await?;
    temp.close()?;
    Ok(())
}

async fn assert_folder(folder: &mut Folder, key: AccessKey) -> Result<()> {
    assert!(folder.commit_state().await.is_ok());
    assert!(folder.root_hash().await.is_ok());

    // Starts with create vault event
    assert_eq!(1, count_records(folder.event_log()).await?);

    // Read when locked is not allowed
    assert!(folder.read_secret(&SecretId::new_v4()).await.is_err());

    folder.unlock(&key).await?;

    // Create a secret
    let secret_id = SecretId::new_v4();
    let secret_name = "label";
    let secret_note = "value";
    let (meta, secret) = mock::note(secret_name, secret_note);
    let row = SecretRow::new(secret_id, meta, secret);
    folder.create_secret(&row).await?;

    assert_eq!(2, count_records(folder.event_log()).await?);

    // Read secret
    let value = folder.read_secret(&secret_id).await?;
    assert!(value.is_some());
    let (meta, secret, _) = value.unwrap();
    assert_eq!(secret_name, meta.label());
    let Secret::Note { text, .. } = secret else {
        panic!("wrong secret type");
    };
    assert_eq!(secret_note, text.expose_secret());

    // Read raw encrypted secret
    assert!(folder.raw_secret(&secret_id).await?.is_some());

    // Update secret
    let secret_name = "label-new";
    let secret_note = "value-new";
    let (meta, secret) = mock::note(secret_name, secret_note);
    folder.update_secret(&secret_id, meta, secret).await?;
    assert_eq!(3, count_records(folder.event_log()).await?);

    // Delete secret
    folder.delete_secret(&secret_id).await?;
    assert_eq!(4, count_records(folder.event_log()).await?);

    // Rename folder
    let folder_name = "test-folder";
    folder.rename_folder(folder_name).await?;
    assert_eq!(5, count_records(folder.event_log()).await?);

    // Update flags
    folder.update_folder_flags(VaultFlags::NO_SYNC).await?;
    assert_eq!(6, count_records(folder.event_log()).await?);

    // Folder description
    let folder_desc = "test-folder-description";
    folder.set_description(folder_desc).await?;
    assert_eq!(7, count_records(folder.event_log()).await?);

    folder.lock();
    Ok(())
}

async fn count_records(
    event_log: Arc<RwLock<FolderEventLog>>,
) -> Result<usize> {
    let event_log = event_log.read().await;
    let mut num_events = 0;

    let stream = event_log.record_stream(false).await;
    pin_mut!(stream);

    while let Some(result) = stream.next().await {
        result?;
        num_events += 1;
    }

    Ok(num_events)
}
