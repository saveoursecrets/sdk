//! Helpers for creating and switching accounts.
use std::{borrow::Cow, sync::Arc};

use sos_net::{
    sdk::{
        account::{Account, AccountLocked, SigninOptions},
        constants::DEFAULT_VAULT_NAME,
        crypto::AccessKey,
        identity::{AccountRef, Identity, PublicIdentity},
        passwd::diceware::generate_passphrase,
        secrecy::{ExposeSecret, SecretString},
        signer::ecdsa::Address,
        vault::{FolderRef, Summary},
        Paths,
    },
    NetworkAccount,
};
use terminal_banner::{Banner, Padding};
use tokio::sync::{mpsc, RwLock};

use crate::helpers::{
    display_passphrase,
    messages::success,
    readline::{choose, choose_password, read_flag, read_password, Choice},
};

use once_cell::sync::OnceCell;

use crate::{Error, Result};

/// Account owner.
pub type Owner = Arc<RwLock<NetworkAccount>>;

/// Current user for the shell REPL.
pub static USER: OnceCell<Owner> = OnceCell::new();

#[derive(Copy, Clone)]
enum AccountPasswordOption {
    Generated,
    Manual,
}

/// Choose an account.
pub async fn choose_account() -> Result<Option<PublicIdentity>> {
    let mut accounts = Identity::list_accounts(None).await?;
    if accounts.is_empty() {
        Ok(None)
    } else if accounts.len() == 1 {
        Ok(Some(accounts.remove(0)))
    } else {
        let options: Vec<Choice<'_, PublicIdentity>> = accounts
            .into_iter()
            .map(|a| Choice(Cow::Owned(a.label().to_string()), a))
            .collect();
        let prompt = Some("Choose account: ");
        let result =
            choose(prompt, &options, true)?.expect("choice to be required");
        return Ok(Some(result.clone()));
    }
}

/// Attempt to resolve a user.
///
/// For the shell REPL this will equal the current USER otherwise
/// the user must sign in to the target account.
pub async fn resolve_user(
    account: Option<&AccountRef>,
    build_search_index: bool,
) -> Result<Owner> {
    if let Some(owner) = USER.get() {
        return Ok(Arc::clone(owner));
    }

    // let account = resolve_account(account)
    //     .await
    //     .ok_or_else(|| Error::NoAccountFound)?;

    /*
    let (mut owner, _) = sign_in(&account).await?;

    // For non-shell we need to initialize the search index
    if USER.get().is_none() {
        if build_search_index {
            owner.initialize_search_index().await?;
        }
        owner.list_folders().await?;
    }

    Ok(Arc::new(RwLock::new(owner)))
    */

    let (user, _) =
        resolve_user_with_password(account, build_search_index).await?;
    Ok(user)
}

/// Attempt to resolve a user with the password.
///
/// Some operations such as changing the account cipher
/// require the account password.
pub async fn resolve_user_with_password(
    account: Option<&AccountRef>,
    build_search_index: bool,
) -> Result<(Owner, SecretString)> {
    let account = resolve_account(account)
        .await
        .ok_or_else(|| Error::NoAccountFound)?;

    let (mut owner, password) = sign_in(&account).await?;

    // For non-shell we need to initialize the search index
    if USER.get().is_none() {
        if build_search_index {
            owner.initialize_search_index().await?;
        }
        owner.list_folders().await?;
    }

    Ok((Arc::new(RwLock::new(owner)), password))
}

/// Take the optional account reference and resolve it.
///
/// If the argument was given use it, otherwise look for an explicit
/// account using the current shell USER otherwise if there is only a single
/// account use it.
pub async fn resolve_account(
    account: Option<&AccountRef>,
) -> Option<AccountRef> {
    if account.is_none() {
        if let Some(owner) = USER.get() {
            let reader = owner.read().await;
            if reader.is_authenticated().await {
                return Some((&*reader).into());
            }
        }

        if let Ok(mut accounts) = Identity::list_accounts(None).await {
            if accounts.len() == 1 {
                return Some(accounts.remove(0).into());
            }
        }
    }
    account.cloned()
}

pub async fn resolve_account_address(
    account: Option<&AccountRef>,
) -> Result<Address> {
    let account = resolve_account(account)
        .await
        .ok_or_else(|| Error::NoAccountFound)?;

    let accounts = Identity::list_accounts(None).await?;
    for info in accounts {
        match account {
            AccountRef::Name(ref name) => {
                if info.label() == name {
                    return Ok(*info.address());
                }
            }
            AccountRef::Address(address) => {
                if info.address() == &address {
                    return Ok(*info.address());
                }
            }
        }
    }
    Err(Error::NoAccountFound)
}

pub async fn resolve_folder(
    user: &Owner,
    folder: Option<&FolderRef>,
) -> Result<Option<Summary>> {
    let owner = user.read().await;
    if let Some(vault) = folder {
        let storage = owner.storage().await?;
        let reader = storage.read().await;
        Ok(Some(
            reader
                .find_folder(vault)
                .cloned()
                .ok_or(Error::FolderNotFound(vault.to_string()))?,
        ))
    } else if let Some(owner) = USER.get() {
        let owner = owner.read().await;
        let storage = owner.storage().await?;
        let reader = storage.read().await;
        let summary =
            reader.current_folder().ok_or(Error::NoVaultSelected)?;
        Ok(Some(summary.clone()))
    } else {
        let storage = owner.storage().await?;
        let reader = storage.read().await;
        Ok(reader.find(|s| s.flags().is_default()).cloned())
    }
}

pub async fn cd_folder(
    user: Owner,
    folder: Option<&FolderRef>,
) -> Result<()> {
    let summary = {
        let owner = user.read().await;
        let storage = owner.storage().await?;
        let reader = storage.read().await;
        let summary = if let Some(vault) = folder {
            Some(
                reader
                    .find_folder(vault)
                    .cloned()
                    .ok_or(Error::FolderNotFound(vault.to_string()))?,
            )
        } else {
            reader.find(|s| s.flags().is_default()).cloned()
        };

        summary.ok_or(Error::NoFolderFound)?
    };
    let owner = user.read().await;
    owner.open_folder(&summary).await?;
    Ok(())
}

/// Verify the primary password for an account.
pub async fn verify(user: Owner) -> Result<bool> {
    let passphrase = read_password(Some("Password: "))?;
    let owner = user.read().await;
    Ok(owner.verify(&AccessKey::Password(passphrase)).await)
}

/// List local accounts.
pub async fn list_accounts(verbose: bool) -> Result<()> {
    let accounts = Identity::list_accounts(None).await?;
    for account in &accounts {
        if verbose {
            println!("{} {}", account.address(), account.label());
        } else {
            println!("{}", account.label());
        }
    }
    if accounts.is_empty() {
        println!("no accounts yet");
    }
    Ok(())
}

pub async fn find_account(
    account: &AccountRef,
) -> Result<Option<PublicIdentity>> {
    let accounts = Identity::list_accounts(None).await?;
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
) -> Result<(NetworkAccount, SecretString)> {
    let account = find_account(account)
        .await?
        .ok_or(Error::NoAccount(account.to_string()))?;
    let passphrase = read_password(Some("Password: "))?;

    let mut owner = NetworkAccount::new_unauthenticated(
        *account.address(),
        None,
        Default::default(),
    )
    .await?;

    let (tx, mut rx) = mpsc::channel::<()>(8);
    tokio::task::spawn(async move {
        while let Some(_) = rx.recv().await {
            let banner = Banner::new()
                .padding(Padding::one())
                .text("Account locked".into())
                .newline()
                .text(
                    "This account is locked because another program is already signed in; this may be another terminal or application window.".into())
                .newline()
                .text(
                    "To continue sign out of the account in the other window.".into())
                .render();
            println!("{}", banner);
        }
    });

    let options = SigninOptions {
        locked: AccountLocked::Notify(tx),
    };

    let key: AccessKey = passphrase.clone().into();
    owner.sign_in_with_options(&key, options).await?;

    Ok((owner, passphrase))
}

/// Switch to a different account.
pub async fn switch(
    account: &AccountRef,
) -> Result<Arc<RwLock<NetworkAccount>>> {
    let (mut owner, _) = sign_in(account).await?;

    owner.initialize_search_index().await?;
    owner.list_folders().await?;

    let mut writer = USER.get().unwrap().write().await;
    *writer = owner;
    Ok(Arc::clone(USER.get().unwrap()))
}

/// Create a new local account.
pub async fn new_account(
    account_name: String,
    folder_name: Option<String>,
) -> Result<()> {
    let account = AccountRef::Name(account_name.clone());
    let account = find_account(&account).await?;

    if account.is_some() {
        return Err(Error::AccountExists(account_name));
    }

    let banner = Banner::new()
        .padding(Padding::one())
        .text("WELCOME".into())
        .newline()
        .text(
            "Your new account requires a primary password; you must memorize this password or you will lose access to your secrets.".into())
        .newline()
        .text(
            "You may generate a strong diceware password or choose your own password; if you choose a password it must be excellent strength.".into())
        .render();
    println!("{}", banner);

    let options = vec![
        Choice(
            Cow::Borrowed("Generated password (recommended)"),
            AccountPasswordOption::Generated,
        ),
        Choice(
            Cow::Borrowed("Choose a password"),
            AccountPasswordOption::Manual,
        ),
    ];

    let is_ci =
        cfg!(any(test, debug_assertions)) && std::env::var("CI").is_ok();

    let password_option = if is_ci {
        AccountPasswordOption::Generated
    } else {
        *choose(None, &options, true)?.expect("choice to be required")
    };
    let is_generated =
        matches!(password_option, AccountPasswordOption::Generated);

    // Generate a primary password
    let passphrase = match password_option {
        AccountPasswordOption::Generated => {
            // Support for CI environments choosing the account password
            if let Ok(password) = std::env::var("SOS_PASSWORD") {
                password.into()
            } else {
                let (passphrase, _) = generate_passphrase()?;
                passphrase
            }
        }
        AccountPasswordOption::Manual => choose_password()?,
    };

    let default_folder_name = folder_name
        .as_ref()
        .map(|s| &s[..])
        .unwrap_or(DEFAULT_VAULT_NAME);

    let mut message = format!(
        r#"* Write identity vault "{}"
* Create default folder "{}""#,
        account_name, default_folder_name,
    );

    if is_generated {
        message.push_str("\n* Master password will be displayed");
    }

    let banner = Banner::new()
        .padding(Padding::one())
        .text("NEW ACCOUNT".into())
        .newline()
        .text(account_name.clone().into())
        .newline()
        .text(
            "Creating a new account will perform the following actions:"
                .into(),
        )
        .newline()
        .text(message.into())
        .render();
    println!("{}", banner);

    let confirmed = read_flag(Some(
        "Are you sure you want to create a new account (y/n)? ",
    ))?;
    if confirmed {
        if is_generated {
            display_passphrase(
                "PRIMARY PASSWORD",
                passphrase.expose_secret(),
            );
        }

        let mut owner = NetworkAccount::new_account_with_builder(
            account_name.clone(),
            passphrase.clone(),
            None,
            Default::default(),
            |builder| {
                builder
                    .create_contacts(true)
                    .create_archive(true)
                    .create_authenticator(true)
                    .create_file_password(true)
            },
        )
        .await?;
        let address = owner.address().to_string();

        let key: AccessKey = passphrase.into();
        owner.sign_in(&key).await?;

        let data_dir = Paths::data_dir()?;
        let message = format!(
            r#"* Account: {} ({})
* Storage: {}"#,
            account_name,
            address,
            data_dir.display(),
        );

        let banner = Banner::new()
            .padding(Padding::one())
            .newline()
            .text(message.into())
            .render();
        println!("{}", banner);

        success("Account created");
    }

    Ok(())
}
