//! Helpers for creating and switching accounts.
use std::{borrow::Cow, sync::Arc};

use sos_core::{
    account::{AccountBuilder, AccountInfo, AccountRef, LocalAccounts},
    passwd::diceware::generate_passphrase,
    secrecy::{ExposeSecret, SecretString},
    storage::StorageDirs,
    vault::{Summary, VaultRef},
};
use sos_node::client::{provider::ProviderFactory, user::UserStorage};
use terminal_banner::{Banner, Padding};
use tokio::sync::RwLock;

use crate::helpers::{
    display_passphrase,
    readline::{read_flag, read_password},
};

use once_cell::sync::OnceCell;

use crate::{Error, Result};

/// Account owner.
pub type Owner = Arc<RwLock<UserStorage>>;

/// Current user for the shell REPL.
pub(crate) static USER: OnceCell<Owner> = OnceCell::new();

/// Attempt to resolve a user.
///
/// For the shell REPL this will equal the current USER otherwise
/// the user must sign in to the target account.
pub async fn resolve_user(
    account: Option<AccountRef>,
    factory: ProviderFactory,
    build_search_index: bool,
) -> Result<Owner> {
    let account = resolve_account(account)
        .await
        .ok_or_else(|| Error::NoAccountFound)?;

    if let Some(owner) = USER.get() {
        return Ok(Arc::clone(owner));
    }

    let (mut owner, _) = sign_in(&account, factory).await?;

    // For non-shell we need to initialize the search index
    if USER.get().is_none() {
        if build_search_index {
            owner.initialize_search_index().await?;
        } else {
            owner.list_folders().await?;
        }
    }

    Ok(Arc::new(RwLock::new(owner)))
}

/// Take the optional account reference and resolve it.
///
/// If the argument was given use it, otherwise look for an explicit
/// account using the current shell USER otherwise if there is only a single
/// account use it.
pub async fn resolve_account(
    account: Option<AccountRef>,
) -> Option<AccountRef> {
    if account.is_none() {
        if let Some(owner) = USER.get() {
            let reader = owner.read().await;
            let account: AccountRef = reader.user.account().into();
            return Some(account);
        }

        if let Ok(mut accounts) = LocalAccounts::list_accounts() {
            if accounts.len() == 1 {
                return Some(accounts.remove(0).into());
            }
        }
    }
    account
}

pub async fn resolve_folder(
    owner: &Owner,
    folder: Option<&VaultRef>,
) -> Result<Option<Summary>> {
    let reader = owner.read().await;
    if let Some(vault) = folder {
        Ok(Some(
            reader
                .storage
                .state()
                .find_vault(&vault)
                .cloned()
                .ok_or(Error::VaultNotAvailable(vault.clone()))?,
        ))
    } else if let Some(owner) = USER.get() {
        let reader = owner.read().await;
        let keeper =
            reader.storage.current().ok_or(Error::NoVaultSelected)?;
        Ok(Some(keeper.summary().clone()))
    } else {
        Ok(reader
            .storage
            .state()
            .find(|s| s.flags().is_default())
            .cloned())
    }
}

/// Verify the master password for an account.
pub async fn verify(user: Owner) -> Result<bool> {
    let passphrase = read_password(Some("Password: "))?;
    let owner = user.read().await;
    Ok(owner.verify(passphrase))
}

/// List local accounts.
pub fn list_accounts(verbose: bool) -> Result<()> {
    let accounts = LocalAccounts::list_accounts()?;
    for account in accounts {
        if verbose {
            println!("{} {}", account.address(), account.label());
        } else {
            println!("{}", account.label());
        }
    }
    Ok(())
}

pub fn find_account(account: &AccountRef) -> Result<Option<AccountInfo>> {
    let accounts = LocalAccounts::list_accounts()?;
    match account {
        AccountRef::Address(address) => {
            Ok(accounts.into_iter().find(|a| a.address() == address))
        }
        AccountRef::Name(label) => {
            Ok(accounts.into_iter().find(|a| a.label() == label))
        }
    }
}

/// Helper to sign in to an account.
pub async fn sign_in(
    account: &AccountRef,
    factory: ProviderFactory,
) -> Result<(UserStorage, SecretString)> {
    let account = find_account(account)?
        .ok_or(Error::NoAccount(account.to_string()))?;
    let passphrase = read_password(Some("Password: "))?;
    let owner =
        UserStorage::new(account.address(), passphrase.clone(), factory)
            .await?;
    Ok((owner, passphrase))
}

/// Switch to a different account.
pub async fn switch(
    account: &AccountRef,
    factory: ProviderFactory,
) -> Result<Arc<RwLock<UserStorage>>> {
    let (owner, _) = sign_in(account, factory).await?;
    let mut writer = USER.get().unwrap().write().await;
    *writer = owner;
    Ok(Arc::clone(USER.get().unwrap()))
}

/// Create a new local account.
pub async fn new_account(
    account_name: String,
    folder_name: Option<String>,
) -> Result<()> {
    // Generate a master passphrase
    let (passphrase, _) = generate_passphrase()?;

    let (identity_vault, new_account) =
        AccountBuilder::new(account_name.clone(), passphrase.clone())
            .save_passphrase(true)
            .create_archive(true)
            .create_authenticator(true)
            .create_contacts(true)
            .create_file_password(true)
            .default_folder_name(folder_name)
            .build()?;

    let address = new_account.address;

    // Get the signing key for the authenticated user
    let identity_dir = StorageDirs::identity_dir()?;
    println!("{}", identity_dir.display());

    let message = format!(
        r#"* Write identity vault called "{}"
* Create a default folder called "{}"
* Master passphrase will be displayed"#,
        account_name,
        new_account.default_vault.summary().name(),
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
            let new_account =
                AccountBuilder::write(identity_vault, new_account)?;

            // Create local provider
            let factory = ProviderFactory::Local;
            let (mut provider, _) =
                factory.create_provider(new_account.user.signer().clone())?;
            provider.authenticate().await?;

            let _ = provider.import_new_account(&new_account).await?;

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
