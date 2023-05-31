use anyhow::Result;

use serial_test::serial;
use std::path::{Path, PathBuf};

use sos_net::client::{provider::ProviderFactory, user::UserStorage};
use sos_sdk::{
    account::{AccountBuilder, ImportedAccount, NewAccount},
    events::{AuditEvent, AuditLogFile},
    hex,
    passwd::diceware::generate_passphrase,
    storage::StorageDirs,
    vault::{
        secret::{
            FileContent, Secret, SecretData, SecretId, SecretMeta, SecretRow,
        },
        Summary,
    },
    vfs::{self, File},
};

use crate::test_utils::setup;

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

    let new_account =
        AccountBuilder::new(account_name.clone(), passphrase.clone())
            .save_passphrase(true)
            .create_archive(true)
            .create_authenticator(false)
            .create_contacts(false)
            .create_file_password(true)
            .finish()
            .await?;

    let factory = ProviderFactory::Local(None);
    let (mut provider, _) = factory
        .create_provider(new_account.user.signer().clone())
        .await?;

    let imported_account = provider.import_new_account(&new_account).await?;
    let NewAccount { address, .. } = new_account;
    let ImportedAccount { summary, .. } = imported_account;

    let mut owner = UserStorage::new(&address, passphrase, factory).await?;
    owner.initialize_search_index().await?;

    let audit_log = owner.dirs().audit_file();
    let events = read_audit_events(audit_log).await?;

    // Reset the cache dir so we don't interfere
    // with other tests
    StorageDirs::clear_cache_dir();

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
