//! Signup a new account.
use crate::{display_passphrase, Error, Result};

use secrecy::{ExposeSecret, SecretString};
use sos_core::{wal::file::WalFile, PatchFile};
use sos_node::{
    cache_dir,
    client::{
        account::{create_account, AccountKey},
        node_cache::NodeCache,
        run_blocking, PassphraseReader, SignerBuilder,
    },
};
use sos_readline::{read_flag, read_password};
use std::{borrow::Cow, path::PathBuf};
use terminal_banner::{Banner, Padding};
use url::Url;

pub struct StdinPassphraseReader {}

impl PassphraseReader for StdinPassphraseReader {
    type Error = sos_readline::Error;

    fn read(&self) -> std::result::Result<SecretString, Self::Error> {
        read_password(Some("Passphrase: "))
    }
}

/// Switch to an account.
pub fn switch(
    server: Url,
    cache_dir: PathBuf,
    keystore_file: PathBuf,
) -> Result<NodeCache<WalFile, PatchFile>> {
    if !keystore_file.exists() {
        return Err(Error::NotFile(keystore_file));
    }
    let reader = StdinPassphraseReader {};
    let signer = SignerBuilder::new(keystore_file)
        .with_passphrase_reader(Box::new(reader))
        .with_use_agent(true)
        .build()?;
    Ok(NodeCache::new_file_cache(server, cache_dir, signer)?)
}

pub fn signup(
    server: Url,
    destination: PathBuf,
    name: Option<String>,
) -> Result<()> {
    if !destination.is_dir() {
        return Err(Error::NotDirectory(destination));
    }

    let client_key = AccountKey::new_random()?;
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
        let cache_dir = cache_dir().ok_or_else(|| Error::NoCache)?;
        if !cache_dir.is_dir() {
            return Err(Error::NotDirectory(cache_dir));
        }

        let (account, _) = run_blocking(create_account(
            server,
            destination,
            name,
            client_key,
            cache_dir,
            None,
        ))?;

        display_passphrase(
            "KEYSTORE PASSPHRASE",
            account.keystore_passphrase.expose_secret(),
        );
        display_passphrase(
            "ENCRYPTION PASSPHRASE",
            account.encryption_passphrase.expose_secret(),
        );
    }
    Ok(())
}
