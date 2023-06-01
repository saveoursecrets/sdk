use anyhow::Result;

use serial_test::serial;
use std::path::Path;

use sos_net::client::{provider::ProviderFactory, user::UserStorage};
use sos_sdk::{
    account::{ImportedAccount, NewAccount},
    events::{AuditEvent, AuditLogFile, EventKind},
    passwd::diceware::generate_passphrase,
    storage::StorageDirs,
    vault::{
        secret::{SecretData, SecretId},
        Summary,
    },
    vfs::File,
};

use crate::test_utils::{mock_note, setup};

#[tokio::test]
#[serial]
async fn integration_audit_trail() -> Result<()> {
    let dirs = setup(1).await?;

    let test_cache_dir = dirs.clients.get(0).unwrap();
    StorageDirs::set_cache_dir(test_cache_dir.clone());
    assert_eq!(StorageDirs::cache_dir(), Some(test_cache_dir.clone()));
    StorageDirs::skeleton().await?;

    let account_name = "Audit trail test".to_string();
    let (passphrase, _) = generate_passphrase()?;
    let factory = ProviderFactory::Local(None);
    let (mut owner, imported_account, _) =
        UserStorage::new_account_with_builder(
            account_name.clone(),
            passphrase.clone(),
            factory.clone(),
            |builder| {
                builder
                    .save_passphrase(false)
                    .create_archive(true)
                    .create_authenticator(false)
                    .create_contacts(false)
                    .create_file_password(false)
            },
        )
        .await?;

    let ImportedAccount { summary, .. } = imported_account;

    owner.initialize_search_index().await?;

    // Make changes to generate audit logs
    let id = create_secret(&mut owner, &summary).await?;

    let secret_data = read_secret(&mut owner, &summary, &id).await?;
    let id = update_secret(&mut owner, &summary, &id, &secret_data).await?;
    delete_secret(&mut owner, &summary, &id).await?;
    
    // Create a new secret so we can archive it
    let id = create_secret(&mut owner, &summary).await?;
    // Archive the secret to generate move event
    archive_secret(&mut owner, &summary, &id).await?;

    // Read on the audit events
    let audit_log = owner.dirs().audit_file();

    let events = read_audit_events(audit_log).await?;
    let mut kinds: Vec<_> = events.iter().map(|e| e.event_kind()).collect();

    //println!("events {:#?}", events);
    //println!("kinds {:#?}", kinds);

    // Created the default folder
    assert!(matches!(kinds.remove(0), EventKind::CreateVault));
    // Created the archive folder
    assert!(matches!(kinds.remove(0), EventKind::CreateVault));
    // Opened the default folder for reading
    assert!(matches!(kinds.remove(0), EventKind::ReadVault));
    // Created a secret
    assert!(matches!(kinds.remove(0), EventKind::CreateSecret));
    // Read a secret
    assert!(matches!(kinds.remove(0), EventKind::ReadSecret));
    // Update a secret
    assert!(matches!(kinds.remove(0), EventKind::UpdateSecret));
    // Deleted a secret
    assert!(matches!(kinds.remove(0), EventKind::DeleteSecret));
    // Created new secret
    assert!(matches!(kinds.remove(0), EventKind::CreateSecret));
    // Moved to archive
    assert!(matches!(kinds.remove(0), EventKind::MoveSecret));

    // Reset the cache dir so we don't interfere
    // with other tests
    StorageDirs::clear_cache_dir();

    Ok(())
}

async fn create_secret(
    owner: &mut UserStorage,
    default_folder: &Summary,
) -> Result<SecretId> {
    let (meta, secret) = mock_note("Audit note", "Note value");
    let (id, _) = owner
        .create_secret(meta, secret, Some(default_folder.clone()))
        .await?;
    Ok(id)
}

async fn read_secret(
    owner: &mut UserStorage,
    default_folder: &Summary,
    id: &SecretId,
) -> Result<SecretData> {
    let (secret_data, _) =
        owner.read_secret(id, Some(default_folder.clone())).await?;
    Ok(secret_data)
}

async fn update_secret(
    owner: &mut UserStorage,
    default_folder: &Summary,
    id: &SecretId,
    secret_data: &SecretData,
) -> Result<SecretId> {
    let mut new_meta = secret_data.meta.clone();
    new_meta.set_label("Audit note updated".to_string());
    let (new_id, _) = owner
        .update_secret(id, new_meta, None, Some(default_folder.clone()), None)
        .await?;
    Ok(new_id)
}

async fn delete_secret(
    owner: &mut UserStorage,
    folder: &Summary,
    id: &SecretId,
) -> Result<()> {
    owner.delete_secret(id, Some(folder.clone())).await?;
    Ok(())
}

async fn archive_secret(
    owner: &mut UserStorage,
    folder: &Summary,
    id: &SecretId,
) -> Result<()> {
    owner.archive(folder, id).await?;
    Ok(())
}

async fn read_audit_events(
    audit_log: impl AsRef<Path>,
) -> Result<Vec<AuditEvent>> {
    let mut events = Vec::new();
    let log_file = AuditLogFile::new(audit_log.as_ref()).await?;
    let mut file = File::open(audit_log.as_ref()).await?;
    let mut it = log_file.iter().await?;
    while let Some(record) = it.next_entry().await? {
        events.push(log_file.read_event(&mut file, &record).await?);
    }
    Ok(events)
}
