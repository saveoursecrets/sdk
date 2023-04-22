//! Helpers for creating and switching accounts.
use std::{borrow::Cow, sync::Arc};

use sos_core::{
    encode,
    identity::AuthenticatedUser,
    parking_lot::RwLock as SyncRwLock,
    passwd::diceware::generate_passphrase,
    search::SearchIndex,
    secrecy::{ExposeSecret, SecretString},
    storage::StorageDirs,
    vault::Gatekeeper,
};
use sos_node::client::{
    account_manager::{
        AccountInfo, AccountManager, DeviceSigner, NewAccountRequest,
        NewAccountResponse,
    },
    provider::{BoxedProvider, ProviderFactory},
    run_blocking, PassphraseReader,
};
use terminal_banner::{Banner, Padding};
use web3_address::ethereum::Address;

use crate::helpers::{
    display_passphrase,
    readline::{read_flag, read_password},
};

use crate::{Error, Result};

pub struct StdinPassphraseReader {}

impl PassphraseReader for StdinPassphraseReader {
    type Error = crate::Error;

    fn read(&self) -> std::result::Result<SecretString, Self::Error> {
        read_password(Some("Passphrase: "))
    }
}

/// List local accounts.
pub fn list_accounts(
) -> Result<()> {
    let accounts = AccountManager::list_accounts()?;
    for account in accounts {
        println!("{} ({})", account.label, account.address);
    }
    Ok(())
}

/// Helper to sign in to an account.
pub fn sign_in(
    account_name: &str,
) -> Result<(
    AccountInfo,
    AuthenticatedUser,
    Gatekeeper,
    DeviceSigner,
    Arc<SyncRwLock<SearchIndex>>,
)> {
    let accounts = AccountManager::list_accounts()?;
    let account = accounts
        .iter()
        .find(|a| a.label == account_name)
        .ok_or(Error::NoAccount(account_name.to_string()))?;

    let reader = StdinPassphraseReader {};
    let passphrase = reader.read()?;
    let identity_index = Arc::new(SyncRwLock::new(SearchIndex::new(None)));
    // Verify the identity vault can be unlocked
    let (info, user, keeper, device_signer) = AccountManager::sign_in(
        &account.address,
        passphrase,
        Arc::clone(&identity_index),
    )?;

    Ok((info, user, keeper, device_signer, identity_index))
}

/// Switch to a different account.
pub fn switch(
    factory: &ProviderFactory,
    account_name: String,
) -> Result<(BoxedProvider, Address)> {
    let (_, user, _, _, _) = sign_in(&account_name)?;
    Ok(factory.create_provider(user.signer)?)
}

/// Create a new local account.
pub fn local_signup(
    account_name: String,
    folder_name: Option<String>,
) -> Result<()> {
    // Generate a master passphrase
    let (passphrase, _) = generate_passphrase()?;

    let account = NewAccountRequest {
        account_name: account_name.clone(),
        passphrase: passphrase.clone(),
        save_passphrase: true,
        create_archive: true,
        create_authenticator: true,
        create_contact: true,
        create_file_password: true,
        default_folder_name: folder_name,
    };

    let NewAccountResponse {
        address,
        user,
        summary,
        default_vault: vault,
        ..
    } = AccountManager::new_account(account)?;

    // Get the signing key for the authenticated user
    let signer = user.signer;
    let identity_dir = StorageDirs::identity_dir()?;
    println!("{}", identity_dir.display());

    let message = format!(
        r#"* Write identity vault called "{}"
* Create a default folder called "{}"
* Master passphrase will be displayed"#,
        account_name,
        summary.name(),
    );

    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::Borrowed(
            "PLEASE READ CAREFULLY",
        ))
        .text(Cow::Owned(format!("Identity: {} ({})", account_name, address)))
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
            // Prepare a provider for account creation
            let factory = ProviderFactory::Local;
            let (mut provider, _) = factory.create_provider(signer)?;
            run_blocking(provider.authenticate())?;

            // Send the default vault for account creation
            let buffer = encode(&vault)?;
            let _summary =
                run_blocking(provider.create_account_with_buffer(buffer))?;

            let cache_dir =
                StorageDirs::cache_dir().ok_or(Error::NoCacheDir)?;
            let message = format!(
                r#"* Identity: {} ({})
* Storage: {}"#,
                account_name,
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
