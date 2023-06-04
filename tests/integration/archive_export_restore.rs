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
    events::WriteEvent,
    signer::{ecdsa::SingleParty, Signer},
    storage::UserPaths,
    vault::{Gatekeeper, Vault, VaultBuilder, VaultFlags},
};
use web3_address::ethereum::Address;

async fn create_archive(
    passphrase: SecretString,
    vaults: Vec<Vault>,
) -> Result<(Address, Vault, Vec<u8>)> {
    let mut archive = Vec::new();
    let mut writer = Writer::new(Cursor::new(&mut archive));

    let (address, identity_vault) =
        Identity::new_login_vault("Mock".to_string(), passphrase).await?;

    let identity = encode(&identity_vault).await?;

    writer = writer.set_identity(&address, &identity).await?;

    for vault in vaults {
        let buffer = encode(&vault).await?;
        writer = writer.add_vault(*vault.id(), &buffer).await?;
    }

    writer.finish().await?;

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
    let dirs = UserPaths::new(dir.path(), &user_id);
    let passphrase = SecretString::new("mock-password".to_owned());
    let mut storage = LocalProvider::new(dirs).await?;

    // Prepare a vault to add to the archive
    let default_vault = VaultBuilder::new()
        .flags(VaultFlags::DEFAULT)
        .password(passphrase.clone(), None)
        .await?;

    let vault_id = *default_vault.id();
    let (meta, secret) = mock_note("Archived note", "Archived note value");
    let expected_meta = meta.clone();
    let expected_secret = secret.clone();
    let mut keeper = Gatekeeper::new(default_vault, None);
    keeper.unlock(passphrase.clone().into()).await?;
    let secret_id = if let WriteEvent::CreateSecret(id, _) =
        keeper.create(meta, secret).await?
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
        create_archive(passphrase.clone(), vec![vault]).await?;

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
    storage
        .open_vault(&vault_summary, passphrase.into(), None)
        .await?;

    if let Some((archive_meta, archive_secret, _)) =
        storage.current().as_ref().unwrap().read(&secret_id).await?
    {
        assert_eq!(expected_meta, archive_meta);
        assert_eq!(expected_secret, archive_secret);
    } else {
        panic!("expected to read secret from restored vault");
    }

    storage.close_vault();

    Ok(())
}
