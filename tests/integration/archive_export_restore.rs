use anyhow::Result;
use serial_test::serial;
use std::io::Cursor;

use crate::test_utils::*;

use secrecy::SecretString;
use tempfile::tempdir;

use sos_net::client::provider::{LocalProvider, StorageProvider};
use sos_sdk::{
    account::{archive::Writer, AccountBackup, Identity, RestoreOptions},
    encode,
    events::SyncEvent,
    signer::{ecdsa::SingleParty, Signer},
    storage::StorageDirs,
    vault::{Gatekeeper, Vault},
};
use web3_address::ethereum::Address;

fn create_archive(
    passphrase: SecretString,
    vaults: Vec<Vault>,
) -> Result<(Address, Vault, Vec<u8>)> {
    let mut archive = Vec::new();
    let mut writer = Writer::new(Cursor::new(&mut archive));

    let (address, identity_vault) =
        Identity::new_login_vault("Mock".to_string(), passphrase)?;

    let identity = encode(&identity_vault)?;

    writer = writer.set_identity(&address, &identity)?;

    for vault in vaults {
        let buffer = encode(&vault)?;
        writer = writer.add_vault(*vault.id(), &buffer)?;
    }

    writer.finish()?;

    Ok((address, identity_vault, archive))
}

#[tokio::test]
#[serial]
async fn integration_archive_local_provider() -> Result<()> {
    // TODO: test creating external file storage
    // TODO: and extracting the archived files

    let dir = tempdir()?;
    let signer = Box::new(SingleParty::new_random());
    let user_id = signer.address()?.to_string();
    let dirs = StorageDirs::new(dir.path(), &user_id);
    dirs.ensure().await?;
    let passphrase = SecretString::new("mock-password".to_owned());
    let mut storage = LocalProvider::new(dirs)?;

    // Prepare a vault to add to the archive
    let mut default_vault: Vault = Default::default();
    default_vault.set_default_flag(true);
    default_vault.initialize(passphrase.clone(), None)?;
    let vault_id = *default_vault.id();
    let (meta, secret) = mock_note("Archived note", "Archived note value");
    let expected_meta = meta.clone();
    let expected_secret = secret.clone();
    let mut keeper = Gatekeeper::new(default_vault, None);
    keeper.unlock(passphrase.clone())?;
    let secret_id = if let SyncEvent::CreateSecret(id, _) =
        keeper.create(meta, secret)?
    {
        id
    } else {
        unreachable!();
    };

    keeper.lock();

    let vault: Vault = keeper.into();

    let options = RestoreOptions {
        selected: vec![vault.summary().clone()],
        passphrase: Some(passphrase.clone()),
        files_dir: None,
    };

    // Create the archive
    let (address, _identity_vault, mut archive) =
        create_archive(passphrase.clone(), vec![vault])?;

    let reader = Cursor::new(&mut archive);

    // Restore from the archive into the provider
    let targets =
        AccountBackup::extract_verify_archive(reader, &options).await?;
    assert_eq!(address, targets.address);

    storage.restore_archive(&targets).await?;

    // Check the vault exists and has the right identifier
    let summaries = storage.load_vaults().await?;
    assert_eq!(1, summaries.len());
    let vault_summary = summaries[0].clone();
    assert_eq!(&vault_id, vault_summary.id());

    // Open the vault so we can check the secret has been restored
    storage.open_vault(&vault_summary, passphrase, None).await?;

    if let Some((archive_meta, archive_secret, _)) =
        storage.current().as_ref().unwrap().read(&secret_id)?
    {
        assert_eq!(expected_meta, archive_meta);
        assert_eq!(expected_secret, archive_secret);
    } else {
        panic!("expected to read secret from restored vault");
    }

    storage.close_vault();

    Ok(())
}
