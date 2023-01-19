//! Signup a new account.
use crate::{display_passphrase, Error, Result};

use secrecy::{ExposeSecret, SecretString};
use sos_core::{
    constants::{IDENTITY_DIR, VAULT_EXT},
    encode, generate_passphrase,
    identity::Identity,
    vault::Vault,
};
use sos_node::{
    cache_dir,
    client::{
        account::{create_account, AccountKey},
        provider::{BoxedProvider, ProviderFactory},
        run_blocking, PassphraseReader, SignerBuilder,
    },
};
use sos_readline::{read_flag, read_password};
use std::{borrow::Cow, path::PathBuf};
use terminal_banner::{Banner, Padding};
use url::Url;
use web3_address::ethereum::Address;

pub struct StdinPassphraseReader {}

impl PassphraseReader for StdinPassphraseReader {
    type Error = sos_readline::Error;

    fn read(&self) -> std::result::Result<SecretString, Self::Error> {
        read_password(Some("Passphrase: "))
    }
}

fn get_identity_dir() -> Result<PathBuf> {
    let cache_dir = cache_dir().ok_or(Error::NoCacheDir)?;
    let identity_dir = cache_dir.join(IDENTITY_DIR);
    if !identity_dir.exists() {
        std::fs::create_dir(&identity_dir)?;
    }
    Ok(identity_dir)
}

fn get_identity_vault(address: &str) -> Result<PathBuf> {
    let identity_dir = get_identity_dir()?;
    let mut identity_vault_file = identity_dir.join(address);
    identity_vault_file.set_extension(VAULT_EXT);
    Ok(identity_vault_file)
}

/// Switch to a different account.
pub fn switch(
    factory: &ProviderFactory,
    keystore_file: PathBuf,
) -> Result<(BoxedProvider, Address)> {
    if !keystore_file.exists() {
        return Err(Error::NotFile(keystore_file));
    }
    let reader = StdinPassphraseReader {};
    let signer = SignerBuilder::new(keystore_file)
        .with_passphrase_reader(Box::new(reader))
        .with_use_agent(true)
        .build()?;
    Ok(factory.create_provider(signer)?)
}

/// Create a new local identity.
pub fn local_signup(name: String, folder_name: Option<String>) -> Result<()> {
    // Generate a master passphrase
    let (passphrase, _) = generate_passphrase()?;

    // Prepare the default vault
    let mut vault: Vault = Default::default();
    vault.set_default_flag(true);
    if let Some(name) = folder_name {
        vault.set_name(name);
    }
    vault.initialize(passphrase.expose_secret())?;

    // Prepare the identity vault
    let (_address, login_vault) =
        Identity::new_login_vault(name.clone(), passphrase.clone())?;

    // Get an authenticated user from the identity vault
    let buffer = encode(&login_vault)?;
    let (user, _) = Identity::login_buffer(buffer, passphrase.clone())?;

    // Get the signing key for the authenticated user
    let signer = user.signer;
    let address = signer.address()?.to_string();
    let identity_dir = get_identity_dir()?;
    let identity_vault_file = get_identity_vault(&address)?;

    println!("{}", identity_dir.display());

    let message = format!(
        r#"* Write identity vault called "{}"
* Create a default folder called "{}"
* Master passphrase will be displayed"#,
        name,
        vault.summary().name(),
    );

    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::Borrowed(
            "PLEASE READ CAREFULLY",
        ))
        .text(Cow::Owned(format!("Identity: {} ({})", name, address)))
        .text(Cow::Borrowed(
            "Your new account will be assigned a master passphrase, you must memorize this passphrase or you will lose access to your secrets.",
        ))
        .text(Cow::Borrowed(
            "Creating a new account will perform the following actions:",
        ))
        .text(Cow::Owned(message))
        .render();
    println!("{}", banner);

    let accepted =
        read_flag(Some("I will memorize my master passphrase (y/n)? "))?;

    if accepted {
        display_passphrase("MASTER PASSPHRASE", passphrase.expose_secret());

        let confirmed = read_flag(Some(
            "Are you sure you want to create a new account (y/n)? ",
        ))?;
        if confirmed {
            // Write out the identity vault
            let buffer = encode(&login_vault)?;
            std::fs::write(identity_vault_file, buffer)?;

            // Prepare a provider for account creation
            let factory = ProviderFactory::Local;
            let (mut provider, _) = factory.create_provider(signer)?;
            run_blocking(provider.authenticate())?;

            // Send the default vault for account creation
            let buffer = encode(&vault)?;
            let _summary =
                run_blocking(provider.create_account_with_buffer(buffer))?;

            let cache_dir = cache_dir().ok_or(Error::NoCacheDir)?;
            let message = format!(
                r#"* Identity: {} ({})
* Storage: {}"#,
                name,
                address,
                cache_dir.display(),
            );

            let banner = Banner::new()
                .padding(Padding::one())
                .text(Cow::Borrowed("Account created ✓"))
                .text(Cow::Owned(message))
                .render();
            println!("{}", banner);
        }
    }

    Ok(())
}

#[deprecated(note = "Use local_signup")]
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
