//! Signup a new account.
use crate::{
    display_passphrase, run_blocking, Cache, Client, ClientCache, Error,
    Result,
};
use sos_core::{
    address::AddressStr, crypto::generate_random_ecdsa_signing_key,
    generate_passphrase, signer::SingleParty,
};
use sos_readline::read_flag;
use std::{borrow::Cow, path::PathBuf, sync::Arc};
use terminal_banner::{Banner, Padding};
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

    let (keystore_passphrase, _) = generate_passphrase()?;

    let message = format!(
        r#"* Write keystore file to {}
* Send the encrypted vault to {}
* Keystore passphrase will be displayed
* Encryption passphrase will be displayed"#,
        keystore_file.display(),
        server
    );

    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::Borrowed(
            "Creating a new account will perform the following actions:",
        ))
        .text(Cow::Owned(message))
        .render();

    println!("{}", banner);

    let prompt = Some("Are you sure (y/n)? ");
    if read_flag(prompt)? {
        let signer: SingleParty = (&signing_key).try_into()?;
        let client = Client::new(server, Arc::new(signer));
        let cache_dir = Cache::cache_dir()?;
        let mut cache = Cache::new(client, cache_dir, true)?;

        let keystore = encrypt(
            &mut rand::thread_rng(),
            signing_key,
            &keystore_passphrase,
            Some(address.to_string()),
        )?;

        let encryption_passphrase = run_blocking(cache.create_account(name))?;
        std::fs::write(keystore_file, serde_json::to_string(&keystore)?)?;

        display_passphrase("KEYSTORE PASSPHRASE", &keystore_passphrase);
        display_passphrase("ENCRYPTION PASSPHRASE", &encryption_passphrase);
    }

    Ok(())
}
