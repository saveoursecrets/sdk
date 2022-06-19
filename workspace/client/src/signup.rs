//! Signup a new account.
use crate::{display_passphrase, run_blocking, Client, Error, Result};
use k256::ecdsa::SigningKey;
use sos_core::{
    address::AddressStr,
    crypto::generate_random_ecdsa_signing_key,
    diceware::generate,
    signer::SingleParty,
    vault::{encode, Vault},
};
use sos_readline::read_flag;
use std::{path::PathBuf, sync::Arc};
use url::Url;
use web3_keystore::encrypt;

pub fn signup(
    server: Url,
    destination: PathBuf,
    name: Option<String>,
) -> Result<()> {
    if !destination.is_dir() {
        return Err(Error::NotDirectory(destination));
    }

    let (signing_key, public_key) = generate_random_ecdsa_signing_key();

    let address: AddressStr = (&public_key).try_into()?;
    let keystore_file = destination.join(&format!("{}.json", address));

    if keystore_file.exists() {
        return Err(Error::FileExists(keystore_file));
    }

    let (keystore_passphrase, _) = generate()?;
    let (encryption_passphrase, _) = generate()?;

    println!("");
    println!("Creating a new account will perform the following actions:");
    println!("");
    println!("* Write keystore file to {}", keystore_file.display());
    println!("* Send the encrypted vault to {}", server);
    println!("* Keystore passphrase will be displayed");
    println!("* Encryption passphrase will be displayed");
    println!("");

    let prompt = Some("Are you sure (y/n)? ");
    if read_flag(prompt)? {
        let signer: SingleParty = (&signing_key).try_into()?;
        let client = Client::new(server, Arc::new(signer));

        let keystore = encrypt(
            &mut rand::thread_rng(),
            signing_key,
            &keystore_passphrase,
            Some(address.to_string()),
        )?;

        let mut vault: Vault = Default::default();
        if let Some(name) = name {
            vault.set_name(name);
        }
        vault.initialize(&encryption_passphrase)?;

        let buffer = encode(&vault)?;
        let response = run_blocking(client.create_account(buffer))?;
        if !response.status().is_success() {
            return Err(Error::AccountCreate(response.status().into()));
        }

        std::fs::write(keystore_file, serde_json::to_string(&keystore)?)?;

        display_passphrase(
            "Keystore passphrase",
            "YOU MUST REMEMBER THIS PASSPHRASE!",
            &keystore_passphrase,
        );

        display_passphrase(
            "Encryption passphrase",
            "YOU MUST REMEMBER THIS PASSPHRASE!",
            &encryption_passphrase,
        );
    }

    Ok(())
}
