use anyhow::{Error, Result};
use serial_test::serial;

mod test_utils;

use test_utils::*;

use sos_client::{create_account, create_signing_key, ClientKey};

#[tokio::test]
#[serial]
async fn account_signup() -> Result<()> {
    use web3_keystore::{decrypt, KeyStore};

    let destination = setup()?;

    let (rx, handle) = spawn()?;
    let _ = rx.await?;

    let server = server();
    let name = None;
    let key = create_signing_key()?;

    let expected_keystore =
        destination.join(&format!("{}.json", key.address()));

    let ClientKey(signing_key, _, _) = &key;
    let expected_signing_key = *signing_key;

    let credentials = create_account(server, destination, name, key).await?;

    assert_eq!(expected_keystore, credentials.keystore_file);
    assert!(expected_keystore.is_file());

    assert!(!credentials.encryption_passphrase.is_empty());
    assert!(!credentials.keystore_passphrase.is_empty());

    let keystore = std::fs::read(&expected_keystore)?;
    let keystore: KeyStore = serde_json::from_slice(&keystore)?;

    let signing_key: [u8; 32] =
        web3_keystore::decrypt(&keystore, &credentials.keystore_passphrase)?
            .as_slice()
            .try_into()?;

    assert_eq!(expected_signing_key, signing_key);

    Ok(())
}

/*
#[tokio::test]
#[serial]
async fn another_test() -> Result<()> {
    println!("another test!!");

    let dir = integration_test_dir();
    let (rx, handle) = spawn()?;
    let _ = rx.await?;

    Ok(())
}
*/
