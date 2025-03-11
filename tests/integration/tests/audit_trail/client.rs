use anyhow::Result;
use sos_backend::BackendTarget;
use sos_client_storage::NewFolderOptions;
use sos_database::open_file;
use sos_test_utils::make_client_backend;

use crate::test_utils::{mock, setup, teardown};
use futures::{pin_mut, StreamExt};
use sos_account::{Account, FolderCreate, LocalAccount, SecretChange};
use sos_audit::AuditEvent;
use sos_migrate::import::ImportTarget;
use sos_sdk::prelude::*;
use sos_vfs as vfs;
use std::{path::PathBuf, sync::Arc};

#[tokio::test]
async fn audit_trail_client_fs() -> Result<()> {
    const TEST_ID: &str = "audit_trail_client";
    // crate::test_utils::init_tracing();
    //

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    // Configure the audit provider
    let paths = Paths::new_client(&data_dir);
    Paths::scaffold(paths.documents_dir()).await?;
    paths.ensure().await?;
    let provider =
        sos_backend::audit::new_fs_provider(paths.audit_file().to_owned());
    sos_backend::audit::init_providers(vec![provider]);

    let account_name = TEST_ID.to_string();
    let (passphrase, _) = generate_passphrase()?;
    let mut account = LocalAccount::new_account_with_builder(
        account_name.to_owned(),
        passphrase.clone(),
        make_client_backend(&paths).await?,
        |builder| {
            builder
                .save_passphrase(false)
                .create_archive(true)
                .create_authenticator(false)
                .create_contacts(true)
                .create_file_password(true)
        },
    )
    .await?;

    let key: AccessKey = passphrase.clone().into();
    account.sign_in(&key).await?;
    let summary = account.default_folder().await.unwrap();

    // Make changes to generate audit logs
    simulate_session(&mut account, &summary, &paths).await?;

    // Read in the audit log events
    let events = read_audit_events().await?;
    let mut kinds: Vec<_> = events.iter().map(|e| e.event_kind()).collect();

    //println!("events {:#?}", events);
    println!("kinds {:#?}", kinds);

    // Created the account
    assert!(matches!(kinds.remove(0), EventKind::CreateAccount));
    // Created the default folder
    assert!(matches!(kinds.remove(0), EventKind::CreateVault));
    // Created the archive folder
    assert!(matches!(kinds.remove(0), EventKind::CreateVault));
    // Created the contacts folder
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

    // Created a new folder
    assert!(matches!(kinds.remove(0), EventKind::CreateVault));
    // Renamed a folder
    assert!(matches!(kinds.remove(0), EventKind::SetVaultName));
    // Exported a folder
    assert!(matches!(kinds.remove(0), EventKind::ExportVault));

    // Imported a folder that updated a vault
    assert!(matches!(kinds.remove(0), EventKind::UpdateVault));
    // Deleted the new folder
    assert!(matches!(kinds.remove(0), EventKind::DeleteVault));

    // Exported an account archive
    assert!(matches!(kinds.remove(0), EventKind::ExportBackupArchive));

    // Exported an unsafe archive
    assert!(matches!(kinds.remove(0), EventKind::ExportUnsafe));

    // Imported an unsafe file
    assert!(matches!(kinds.remove(0), EventKind::ImportUnsafe));
    assert!(matches!(kinds.remove(0), EventKind::CreateVault));

    // Create event for first contact
    assert!(matches!(kinds.remove(0), EventKind::CreateSecret));
    // Create event for second contact
    assert!(matches!(kinds.remove(0), EventKind::CreateSecret));
    // Contacts import event
    assert!(matches!(kinds.remove(0), EventKind::ImportContacts));

    // Contacts export event
    assert!(matches!(kinds.remove(0), EventKind::ExportContacts));

    // Deleted the account
    assert!(matches!(kinds.remove(0), EventKind::DeleteAccount));

    // Imported an account archive
    assert!(matches!(kinds.remove(0), EventKind::ImportBackupArchive));

    teardown(TEST_ID).await;

    Ok(())
}

async fn simulate_session(
    account: &mut LocalAccount,
    default_folder: &Summary,
    paths: &Arc<Paths>,
) -> Result<()> {
    // Create a secret
    let (meta, secret) = mock::note("Audit note", "Note value");
    let SecretChange { id, .. } = account
        .create_secret(meta, secret, default_folder.id().into())
        .await?;

    // Read the secret
    let (secret_data, _) =
        account.read_secret(&id, Some(default_folder.id())).await?;
    // Update the secret
    let mut new_meta = secret_data.meta().clone();
    new_meta.set_label("Audit note updated".to_string());
    let SecretChange { id, .. } = account
        .update_secret(&id, new_meta, None, default_folder.id().into())
        .await?;
    // Delete the secret
    account
        .delete_secret(&id, default_folder.id().into())
        .await?;

    // Create a new secret so we can archive it
    let (meta, secret) =
        mock::note("Audit note to archive", "Note value to archive");
    let SecretChange { id, .. } = account
        .create_secret(meta, secret, default_folder.id().into())
        .await?;
    // Archive the secret to generate move event
    account
        .archive(default_folder.id(), &id, Default::default())
        .await?;
    // Create a new folder
    let FolderCreate {
        folder: new_folder, ..
    } = account
        .create_folder(NewFolderOptions::new("New folder".to_string()))
        .await?;
    // Rename the folder
    account
        .rename_folder(new_folder.id(), "New name".to_string())
        .await?;

    let exported_folder =
        paths.documents_dir().join("audit-trail-vault-export.vault");
    let (export_passphrase, _) = generate_passphrase()?;
    account
        .export_folder(
            &exported_folder,
            new_folder.id(),
            export_passphrase.clone().into(),
            true,
        )
        .await?;

    account
        .import_folder(
            exported_folder,
            export_passphrase.clone().into(),
            true,
        )
        .await?;

    // Delete the new folder
    account.delete_folder(new_folder.id()).await?;

    // Export an account backup archive
    let archive = paths
        .documents_dir()
        .join("audit-trail-exported-archive.zip");
    account.export_backup_archive(&archive).await?;

    let unsafe_archive =
        paths.documents_dir().join("audit-trail-unsafe-archive.zip");
    account.export_unsafe_archive(unsafe_archive).await?;

    let import_file = "../fixtures/migrate/bitwarden-export.csv";
    let import_target = ImportTarget {
        format: "bitwarden.csv".parse()?,
        path: PathBuf::from(import_file),
        folder_name: "Bitwarden folder".to_string(),
    };
    account.import_file(import_target).await?;

    let contacts = "../fixtures/contacts.vcf";
    let vcard = vfs::read_to_string(contacts).await?;
    account.import_contacts(&vcard, |_| {}).await?;

    let exported_contacts = paths
        .documents_dir()
        .join("audit-trail-exported-contacts.vcf");
    account.export_all_contacts(exported_contacts).await?;

    // Delete the account
    account.delete_account().await?;

    let target = if paths.is_using_db() {
        let client = open_file(paths.database_file()).await?;
        BackendTarget::Database(paths.clone(), client)
    } else {
        BackendTarget::FileSystem(paths.clone())
    };

    LocalAccount::import_backup_archive(archive, &target).await?;

    Ok(())
}

async fn read_audit_events() -> Result<Vec<AuditEvent>> {
    let provider = sos_backend::audit::providers().unwrap().get(0).unwrap();

    let stream = provider.audit_stream(false).await?;
    pin_mut!(stream);

    let events = stream.collect::<Vec<_>>().await;
    let mut audit_events = Vec::new();
    for event in events {
        audit_events.push(event?);
    }
    Ok(audit_events)
}
