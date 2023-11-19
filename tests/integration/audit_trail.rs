use anyhow::Result;

use secrecy::SecretString;
use serial_test::serial;
use std::path::{Path, PathBuf};

use sos_net::{
    client::user::UserStorage,
    migrate::import::ImportTarget,
    sdk::{
        account::RestoreOptions,
        events::{AuditEvent, AuditLogFile, EventKind},
        passwd::diceware::generate_passphrase,
        storage::AppPaths,
        vault::Summary,
        vfs::{self, File},
    },
};

use crate::test_utils::{create_local_account, mock_note, setup};

#[tokio::test]
#[serial]
async fn integration_audit_trail() -> Result<()> {
    let mut dirs = setup(1).await?;
    let test_data_dir = dirs.clients.remove(0);

    let (mut owner, _, summary, passphrase) =
        create_local_account("audit_trail", Some(test_data_dir.clone())).await?;

    // Make changes to generate audit logs
    simulate_session(&mut owner, &summary, passphrase, &test_data_dir).await?;

    // Read in the audit log events
    let paths = owner.paths().await;
    let audit_log = paths.audit_file();
    let events = read_audit_events(audit_log).await?;
    let mut kinds: Vec<_> = events.iter().map(|e| e.event_kind()).collect();

    //println!("events {:#?}", events);
    //println!("kinds {:#?}", kinds);

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
    // Imported a folder
    assert!(matches!(kinds.remove(0), EventKind::ImportVault));
    // Deleted the new folder
    assert!(matches!(kinds.remove(0), EventKind::DeleteVault));

    // Exported an account archive
    assert!(matches!(kinds.remove(0), EventKind::ExportBackupArchive));
    // Imported an account archive
    assert!(matches!(kinds.remove(0), EventKind::ImportBackupArchive));

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

    // Reset the cache dir so we don't interfere
    // with other tests
    AppPaths::clear_data_dir();

    Ok(())
}

async fn simulate_session(
    owner: &mut UserStorage,
    default_folder: &Summary,
    passphrase: SecretString,
    test_data_dir: &PathBuf,
) -> Result<()> {
    // Create a secret
    let (meta, secret) = mock_note("Audit note", "Note value");
    let (id, _) = owner
        .create_secret(meta, secret, default_folder.clone().into())
        .await?;
    // Read the secret
    let (secret_data, _) =
        owner.read_secret(&id, Some(default_folder.clone())).await?;
    // Update the secret
    let mut new_meta = secret_data.meta.clone();
    new_meta.set_label("Audit note updated".to_string());
    let (id, _) = owner
        .update_secret(
            &id,
            new_meta,
            None,
            default_folder.clone().into(),
            None,
        )
        .await?;
    // Delete the secret
    owner
        .delete_secret(&id, default_folder.clone().into())
        .await?;
    // Create a new secret so we can archive it
    let (meta, secret) =
        mock_note("Audit note to archive", "Note value to archive");
    let (id, _) = owner
        .create_secret(meta, secret, default_folder.clone().into())
        .await?;
    // Archive the secret to generate move event
    owner
        .archive(default_folder, &id, Default::default())
        .await?;
    // Create a new folder
    let new_folder = owner.create_folder("New folder".to_string()).await?;
    // Rename the folder
    owner
        .rename_folder(&new_folder, "New name".to_string())
        .await?;

    let exported_folder = "target/audit-trail-vault-export.vault";
    let (export_passphrase, _) = generate_passphrase()?;
    owner
        .export_folder(
            exported_folder,
            &new_folder,
            export_passphrase.clone().into(),
            true,
        )
        .await?;

    owner
        .import_folder(
            exported_folder,
            export_passphrase.clone().into(),
            true,
        )
        .await?;

    // Delete the new folder
    owner.delete_folder(&new_folder).await?;

    // Export an account backup archive
    let archive = "target/audit-trail-exported-archive.zip";
    owner.export_backup_archive(archive).await?;

    let restore_options = RestoreOptions {
        selected: vec![default_folder.clone()],
        passphrase: Some(passphrase),
        files_dir: None,
    };

    UserStorage::restore_backup_archive(
        Some(owner),
        archive,
        restore_options,
        Some(test_data_dir.clone()),
    )
    .await?;

    let unsafe_archive = "target/audit-trail-unsafe-archive.zip";
    owner.export_unsafe_archive(unsafe_archive).await?;

    let import_file = "workspace/migrate/fixtures/bitwarden-export.csv";
    let import_target = ImportTarget {
        format: "bitwarden.csv".parse()?,
        path: PathBuf::from(import_file),
        folder_name: "Bitwarden folder".to_string(),
    };
    owner.import_file(import_target).await?;

    let contacts = "tests/fixtures/contacts.vcf";
    let vcard = vfs::read_to_string(contacts).await?;
    owner.import_vcard(&vcard, |_| {}).await?;

    let exported_contacts = "target/audit-trail-exported-contacts.vcf";
    owner.export_all_vcards(exported_contacts).await?;

    // Delete the account
    owner.delete_account().await?;

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
