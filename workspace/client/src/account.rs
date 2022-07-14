//! Signup a new account.
use crate::{display_passphrase, run_blocking, Error, Result};
use sos_core::{
    address::AddressStr, crypto::generate_random_ecdsa_signing_key,
    generate_passphrase, signer::SingleParty, vault::Summary,
};
use sos_node::{
    create_account, create_signing_key, ClientBuilder, FileCache,
    PassphraseReader,
};
use sos_readline::{read_flag, read_password};
use std::{borrow::Cow, path::PathBuf, sync::Arc};
use terminal_banner::{Banner, Padding};
use url::Url;
use web3_keystore::encrypt;

pub struct StdinPassphraseReader {}

impl PassphraseReader for StdinPassphraseReader {
    type Error = sos_readline::Error;

    fn read(&self) -> std::result::Result<String, Self::Error> {
        read_password(Some("Passphrase: "))
    }
}

/// Switch to an account.
pub fn switch(
    server: Url,
    cache_dir: PathBuf,
    keystore_file: PathBuf,
) -> Result<FileCache> {
    if !keystore_file.exists() {
        return Err(Error::NotFile(keystore_file));
    }
    let reader = StdinPassphraseReader {};
    let client =
        ClientBuilder::new(server, keystore_file)
            .with_passphrase_reader(Box::new(reader))
            .build()?;
    Ok(FileCache::new(client, cache_dir, true)?)
}

pub fn signup(
    server: Url,
    destination: PathBuf,
    name: Option<String>,
) -> Result<()> {
    if !destination.is_dir() {
        return Err(Error::NotDirectory(destination));
    }

    let client_key = create_signing_key()?;
    let keystore_file =
        destination.join(&format!("{}.json", client_key.address()));
    if keystore_file.exists() {
        return Err(Error::FileExists(keystore_file));
    }

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
        let (account, _) = run_blocking(create_account(
            server,
            destination,
            name,
            client_key,
            FileCache::cache_dir()?,
        ))?;

        display_passphrase(
            "KEYSTORE PASSPHRASE",
            &account.keystore_passphrase,
        );
        display_passphrase(
            "ENCRYPTION PASSPHRASE",
            &account.encryption_passphrase,
        );
    }
    Ok(())
}
