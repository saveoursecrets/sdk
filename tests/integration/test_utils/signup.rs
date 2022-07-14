use anyhow::Result;

use super::{server, TestDirs};

use sos_core::address::AddressStr;

use sos_node::{
    create_account, create_signing_key, ClientCache, ClientCredentials,
    ClientKey, FileCache,
};
use web3_keystore::{decrypt, KeyStore};

pub async fn signup(
    dirs: &TestDirs,
    client_index: usize,
) -> Result<(AddressStr, ClientCredentials, FileCache)> {
    let TestDirs {
        target: destination,
        clients,
        ..
    } = dirs;

    let cache_dir = clients.get(client_index).unwrap().to_path_buf();

    let server = server();
    let name = None;
    let key = create_signing_key()?;

    let address = key.address().to_owned();

    let expected_keystore =
        destination.join(&format!("{}.json", key.address()));

    let ClientKey(signing_key, _, _) = &key;
    let expected_signing_key = *signing_key;

    let (credentials, mut disc_cache) = create_account(
        server,
        destination.to_path_buf(),
        name,
        key,
        cache_dir,
    )
    .await?;

    assert_eq!(expected_keystore, credentials.keystore_file);
    assert!(expected_keystore.is_file());

    assert!(!credentials.encryption_passphrase.is_empty());
    assert!(!credentials.keystore_passphrase.is_empty());

    let keystore = std::fs::read(&expected_keystore)?;
    let keystore: KeyStore = serde_json::from_slice(&keystore)?;

    let signing_key: [u8; 32] =
        decrypt(&keystore, &credentials.keystore_passphrase)?
            .as_slice()
            .try_into()?;

    assert_eq!(expected_signing_key, signing_key);

    let _ = disc_cache.load_vaults().await?;

    Ok((address, credentials, disc_cache))
}
