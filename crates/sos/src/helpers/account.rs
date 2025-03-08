//! Helpers for creating and switching accounts.
use crate::helpers::{
    display_passphrase,
    messages::success,
    readline::{choose, choose_password, read_flag, read_password, Choice},
};
use crate::{Error, Result};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use secrecy::{ExposeSecret, SecretString};
use sos_account::Account;
use sos_backend::BackendTarget;
use sos_core::{
    constants::DEFAULT_VAULT_NAME, crypto::AccessKey, AccountId, AccountRef,
    FolderRef, Paths, PublicIdentity,
};
use sos_net::{NetworkAccount, NetworkAccountSwitcher};
use sos_password::diceware::generate_passphrase;
use sos_vault::Summary;
use std::{borrow::Cow, sync::Arc};
use terminal_banner::{Banner, Padding};
use tokio::sync::RwLock;

/// Account owner.
pub type Owner = Arc<RwLock<NetworkAccountSwitcher>>;

/// Current user for the shell REPL.
pub static USER: Lazy<Owner> =
    Lazy::new(|| Arc::new(RwLock::new(NetworkAccountSwitcher::new())));

/// Flag used to test is we are running a shell context.
pub static SHELL: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));

#[derive(Copy, Clone)]
enum AccountPasswordOption {
    Generated,
    Manual,
}

/// Choose an account.
pub async fn choose_account() -> Result<Option<PublicIdentity>> {
    let paths = Paths::new_client(Paths::data_dir()?);
    let target = BackendTarget::from_paths(&paths).await?;
    let mut accounts = target.list_accounts().await?;
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
    let is_shell = *SHELL.lock();
    if is_shell {
        return Ok(Arc::clone(&USER));
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
    let is_shell = *SHELL.lock();
    let account = resolve_account(account)
        .await?
        .ok_or_else(|| Error::NoAccountFound)?;

    let password = sign_in(&account).await?;

    // For non-shell we need to initialize the search index
    if !is_shell {
        let mut owner = USER.write().await;
        let owner = owner
            .selected_account_mut()
            .ok_or(Error::NoSelectedAccount)?;
        if build_search_index {
            owner.initialize_search_index().await?;
        }
        owner.list_folders().await?;
    }

    Ok((Arc::clone(&USER), password))
}

/// Take the optional account reference and resolve it.
///
/// If the argument was given use it, otherwise look for an explicit
/// account using the current shell USER otherwise if there is only a single
/// account use it.
pub async fn resolve_account(
    account: Option<&AccountRef>,
) -> Result<Option<AccountRef>> {
    let is_shell = *SHELL.lock();
    if account.is_none() {
        if is_shell {
            let owner = USER.read().await;
            if let Some(owner) = owner.selected_account() {
                if owner.is_authenticated().await {
                    return Ok(Some((&*owner).into()));
                }
            }
        }

        let paths = Paths::new_client(Paths::data_dir()?);
        let target = BackendTarget::from_paths(&paths).await?;
        if let Ok(mut accounts) = target.list_accounts().await {
            if accounts.len() == 1 {
                return Ok(Some(accounts.remove(0).into()));
            }
        }
    }
    Ok(account.cloned())
}

pub async fn resolve_account_address(
    account: Option<&AccountRef>,
) -> Result<AccountId> {
    let account = resolve_account(account)
        .await?
        .ok_or_else(|| Error::NoAccountFound)?;

    let paths = Paths::new_client(Paths::data_dir()?);
    let target = BackendTarget::from_paths(&paths).await?;
    let accounts = target.list_accounts().await?;
    for info in accounts {
        match account {
            AccountRef::Name(ref name) => {
                if info.label() == name {
                    return Ok(*info.account_id());
                }
            }
            AccountRef::Id(address) => {
                if info.account_id() == &address {
                    return Ok(*info.account_id());
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
    let is_shell = *SHELL.lock();
    let owner = user.read().await;
    let owner = owner.selected_account().ok_or(Error::NoSelectedAccount)?;
    if let Some(vault) = folder {
        Ok(Some(
            owner
                .find_folder(vault)
                .await
                .ok_or(Error::FolderNotFound(vault.to_string()))?,
        ))
    } else if is_shell {
        let owner = USER.read().await;
        let owner =
            owner.selected_account().ok_or(Error::NoSelectedAccount)?;
        let summary = owner
            .current_folder()
            .await?
            .ok_or(Error::NoVaultSelected)?;
        Ok(Some(summary.clone()))
    } else {
        Ok(owner.find(|s| s.flags().is_default()).await)
    }
}

pub async fn cd_folder(folder: Option<&FolderRef>) -> Result<()> {
    let summary = {
        let owner = USER.read().await;
        let owner =
            owner.selected_account().ok_or(Error::NoSelectedAccount)?;
        let summary = if let Some(vault) = folder {
            Some(
                owner
                    .find_folder(vault)
                    .await
                    .ok_or(Error::FolderNotFound(vault.to_string()))?,
            )
        } else {
            owner.find(|s| s.flags().is_default()).await
        };

        summary.ok_or(Error::NoFolderFound)?
    };
    let owner = USER.read().await;
    let owner = owner.selected_account().ok_or(Error::NoSelectedAccount)?;
    owner.open_folder(summary.id()).await?;
    Ok(())
}

/// Verify the primary password for an account.
pub async fn verify(user: Owner) -> Result<bool> {
    let passphrase = read_password(Some("Password: "))?;
    let owner = user.read().await;
    let owner = owner.selected_account().ok_or(Error::NoSelectedAccount)?;
    Ok(owner.verify(&AccessKey::Password(passphrase)).await)
}

/// List local accounts.
pub async fn list_accounts(verbose: bool) -> Result<()> {
    let paths = Paths::new_client(Paths::data_dir()?);
    let target = BackendTarget::from_paths(&paths).await?;
    let accounts = target.list_accounts().await?;
    for account in &accounts {
        if verbose {
            println!("{} {}", account.account_id(), account.label());
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
    let paths = Paths::new_client(Paths::data_dir()?);
    let target = BackendTarget::from_paths(&paths).await?;
    let accounts = target.list_accounts().await?;
    match account {
        AccountRef::Id(id) => {
            Ok(accounts.into_iter().find(|a| a.account_id() == id))
        }
        AccountRef::Name(label) => {
            Ok(accounts.into_iter().find(|a| a.label() == label))
        }
    }
}

/// Helper to sign in to an account.
pub async fn sign_in(account: &AccountRef) -> Result<SecretString> {
    let account = find_account(account)
        .await?
        .ok_or(Error::NoAccount(account.to_string()))?;

    let mut owner = USER.write().await;

    let is_authenticated = {
        if let Some(current) = owner
            .iter()
            .find(|a| a.account_id() == account.account_id())
        {
            current.is_authenticated().await
        } else {
            false
        }
    };

    let paths = Paths::new_client(Paths::data_dir()?)
        .with_account_id(account.account_id());

    let passphrase = if !is_authenticated {
        let target = BackendTarget::from_paths(&paths).await?;
        let mut current_account = NetworkAccount::new_unauthenticated(
            *account.account_id(),
            target,
            Default::default(),
        )
        .await?;

        let passphrase = read_password(Some("Password: "))?;
        let key: AccessKey = passphrase.clone().into();
        current_account.sign_in(&key).await?;

        owner.add_account(current_account);
        passphrase
    } else {
        SecretString::new("".into())
    };

    owner.switch_account(account.account_id());

    Ok(passphrase)
}

/// Switch to a different account.
pub async fn switch(account: &AccountRef) -> Result<Owner> {
    sign_in(account).await?;
    {
        let mut owner = USER.write().await;
        let owner = owner
            .selected_account_mut()
            .ok_or(Error::NoSelectedAccount)?;

        owner.initialize_search_index().await?;
        owner.list_folders().await?;
    }
    Ok(Arc::clone(&USER))
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

        let paths = Paths::new_client(Paths::data_dir()?);
        let target = BackendTarget::from_paths(&paths).await?;

        let mut owner = NetworkAccount::new_account_with_builder(
            account_name.clone(),
            passphrase.clone(),
            target,
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
        let account_id = owner.account_id().to_string();

        let key: AccessKey = passphrase.into();
        owner.sign_in(&key).await?;

        let data_dir = Paths::data_dir()?;
        let message = format!(
            r#"* Account: {} ({})
* Storage: {}"#,
            account_name,
            account_id,
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
