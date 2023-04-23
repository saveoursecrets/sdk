//! Helpers for creating and switching accounts.
use std::{borrow::Cow, path::PathBuf, sync::Arc};

use parking_lot::RwLock as SyncRwLock;
use sos_core::{
    account::{
        AccountBackup, AccountBuilder, AccountInfo, DeviceSigner,
        LocalAccounts, Login, RestoreOptions, AuthenticatedUser,
        archive::Inventory,
    },
    passwd::diceware::generate_passphrase,
    search::SearchIndex,
    secrecy::{ExposeSecret, SecretString},
    storage::StorageDirs,
    vault::Gatekeeper,
};
use sos_node::client::provider::{BoxedProvider, ProviderFactory};
use terminal_banner::{Banner, Padding};
use web3_address::ethereum::Address;

use crate::helpers::{
    display_passphrase,
    readline::{read_flag, read_password},
};

use crate::{Error, Result};

/// List local accounts.
pub fn list_accounts(verbose: bool) -> Result<()> {
    let accounts = LocalAccounts::list_accounts()?;
    for account in accounts {
        if verbose {
            println!("{} {}", account.address, account.label);
        } else {
            println!("{}", account.label);
        }
    }
    Ok(())
}

/// Print account info.
pub async fn account_info(
    account_name: &str,
    verbose: bool,
    system: bool,
) -> Result<()> {
    let (info, _, _, _, _, _) = sign_in(account_name).await?;
    let folders = LocalAccounts::list_local_vaults(&info.address, system)?;
    for (summary, _) in folders {
        if verbose {
            println!("{} {}", summary.id(), summary.name());
        } else {
            println!("{}", summary.name());
        }
    }
    Ok(())
}

/// Create a backup zip archive.
pub fn account_backup(
    account_name: &str,
    output: PathBuf,
    force: bool,
) -> Result<()> {
    if !force && output.exists() {
        return Err(Error::FileExists(output));
    }

    let account = find_account(account_name)?
        .ok_or(Error::NoAccount(account_name.to_string()))?;
    AccountBackup::export_archive_file(&output, &account.address)?;
    Ok(())
}

/// Restore from a zip archive.
pub async fn account_restore(input: PathBuf) -> Result<Option<AccountInfo>> {
    if !input.exists() || !input.is_file() {
        return Err(Error::NotFile(input));
    }

    let buffer = std::fs::read(input)?;
    let inventory: Inventory =
        AccountBackup::restore_archive_inventory(buffer.as_slice())?;
    let account = find_account_by_address(&inventory.manifest.address)?;

    let (provider, passphrase) = if let Some(account) = account {
        let confirmed = read_flag(Some(
            "Overwrite all account data from backup? (y/n) ",
        ))?;
        if !confirmed {
            return Ok(None);
        }

        let (_, user, _, _, _, _) = sign_in(&account.label).await?;
        let factory = ProviderFactory::Local;
        let (provider, _) = factory.create_provider(user.signer)?;
        (Some(provider), None)
    } else {
        (None, None)
    };

    let files_dir = StorageDirs::files_dir(&inventory.manifest.address)?;
    let options = RestoreOptions {
        selected: inventory.vaults,
        passphrase,
        files_dir: Some(files_dir),
        files_dir_builder: None,
    };
    let (targets, account) = AccountBackup::restore_archive_buffer(
        buffer,
        options,
        provider.is_some(),
    )
    .await?;

    if let Some(mut provider) = provider {
        provider.restore_archive(&targets).await?;
    }

    Ok(Some(account))
}

fn find_account(account_name: &str) -> Result<Option<AccountInfo>> {
    let accounts = LocalAccounts::list_accounts()?;
    Ok(accounts.into_iter().find(|a| a.label == account_name))
}

fn find_account_by_address(address: &str) -> Result<Option<AccountInfo>> {
    let accounts = LocalAccounts::list_accounts()?;
    Ok(accounts.into_iter().find(|a| a.address == address))
}

/// Helper to sign in to an account.
pub async fn sign_in(
    account_name: &str,
) -> Result<(
    AccountInfo,
    AuthenticatedUser,
    Gatekeeper,
    DeviceSigner,
    Arc<SyncRwLock<SearchIndex>>,
    SecretString,
)> {
    let account = find_account(account_name)?
        .ok_or(Error::NoAccount(account_name.to_string()))?;

    let passphrase = read_password(Some("Password: "))?;
    let identity_index = Arc::new(SyncRwLock::new(SearchIndex::new(None)));
    // Verify the identity vault can be unlocked
    let (info, user, keeper, device_signer) = Login::sign_in(
        &account.address,
        passphrase.clone(),
        Arc::clone(&identity_index),
    )
    .await?;

    Ok((
        info,
        user,
        keeper,
        device_signer,
        identity_index,
        passphrase,
    ))
}

/// Switch to a different account.
pub async fn switch(
    factory: &ProviderFactory,
    account_name: String,
) -> Result<(BoxedProvider, Address)> {
    let (_, user, _, _, _, _) = sign_in(&account_name).await?;
    Ok(factory.create_provider(user.signer)?)
}

/// Create a new local account.
pub async fn local_signup(
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

    let address = new_account.address.clone();

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
                factory.create_provider(new_account.user.signer.clone())?;
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
