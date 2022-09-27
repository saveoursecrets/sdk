use anyhow::Result;

use super::{server, TestDirs};

use sos_core::{
    signer::{BoxedSigner, SingleParty},
    wal::file::WalFile,
    PatchFile,
};

use web3_address::ethereum::Address;

use secrecy::ExposeSecret;
use sos_node::client::{
    account::{create_account, AccountCredentials, AccountKey},
    provider::{RemoteProvider, StorageProvider},
};
use web3_keystore::{decrypt, KeyStore};

pub async fn signup(
    dirs: &TestDirs,
    client_index: usize,
) -> Result<(
    Address,
    AccountCredentials,
    RemoteProvider<WalFile, PatchFile>,
    BoxedSigner,
)> {
    let TestDirs {
        target: destination,
        clients,
        ..
    } = dirs;

    let cache_dir = clients.get(client_index).unwrap().to_path_buf();

    let server = server();
    let name = None;
    let key = AccountKey::new_random()?;

    let address = key.address().to_owned();

    let expected_keystore =
        destination.join(&format!("{}.json", key.address()));

    let AccountKey(signing_key, _) = &key;
    let expected_signing_key = signing_key.to_bytes();

    let (credentials, mut node_cache) = create_account(
        server,
        destination.to_path_buf(),
        name,
        key,
        cache_dir,
        None,
    )
    .await?;

    assert_eq!(expected_keystore, credentials.keystore_file);
    assert!(expected_keystore.is_file());

    assert!(!credentials.encryption_passphrase.expose_secret().is_empty());
    assert!(!credentials.keystore_passphrase.expose_secret().is_empty());

    let keystore = std::fs::read(&expected_keystore)?;
    let keystore: KeyStore = serde_json::from_slice(&keystore)?;

    let signing_key: [u8; 32] =
        decrypt(&keystore, credentials.keystore_passphrase.expose_secret())?
            .as_slice()
            .try_into()?;

    let signer: SingleParty = (&signing_key).try_into()?;
    let signer: BoxedSigner = Box::new(signer);

    assert_eq!(expected_signing_key, signing_key);

    let _ = node_cache.load_vaults().await?;

    Ok((address, credentials, node_cache, signer))
}
