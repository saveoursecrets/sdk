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
    //let expected_signing_key = signing_key.to_bytes();

    let signer: BoxedSigner = signing_key.clone();

    //assert_eq!(expected_signing_key, signing_key);

    let (credentials, mut node_cache) = create_account(
        server,
        destination.to_path_buf(),
        name,
        key,
        cache_dir,
        None,
    )
    .await?;

    assert!(!credentials.encryption_passphrase.expose_secret().is_empty());

    let _ = node_cache.load_vaults().await?;

    Ok((address, credentials, node_cache, signer))
}
