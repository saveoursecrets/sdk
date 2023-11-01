use std::{borrow::Cow, sync::Arc};

use terminal_banner::{Banner, Padding};

use sos_net::{
    client::{provider::ProviderFactory, user::UserStorage},
    sdk::{account::AccountRef, storage::AppPaths, vault::VaultRef, vfs},
    FileLocks,
};

use tokio::sync::RwLock;

use crate::{
    helpers::{
        account::{cd_folder, choose_account, sign_in, USER},
        readline,
    },
    Error, Result, TARGET,
};

use super::repl::exec;

const WELCOME: &str = include_str!("welcome.txt");

/// Print the welcome information.
fn welcome(factory: &ProviderFactory) -> Result<()> {
    let help_info = r#"Type "help", "--help" or "-h" for command usage
Type "quit" or "q" to exit"#;
    let status_info = format!("Provider: {}", factory);
    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::from(WELCOME))
        .text(Cow::from(help_info))
        .text(Cow::Owned(status_info))
        .render();
    println!("{}", banner);
    Ok(())
}

/// Loop sign in for shell authentication.
async fn auth(
    account: &AccountRef,
    factory: ProviderFactory,
) -> Result<UserStorage> {
    loop {
        match sign_in(account, factory.clone()).await {
            Ok((owner, _)) => return Ok(owner),
            Err(e) => {
                tracing::error!(target: TARGET, "{}", e);
                if matches!(e, Error::NoAccount(_)) {
                    std::process::exit(1);
                } else if e.is_interrupted() {
                    std::process::exit(0);
                }
            }
        }
    }
}

pub async fn run(
    factory: ProviderFactory,
    mut account: Option<AccountRef>,
    folder: Option<VaultRef>,
) -> Result<()> {
    let data_dir = AppPaths::data_dir().map_err(|_| Error::NoCache)?;
    if !vfs::metadata(&data_dir).await?.is_dir() {
        return Err(Error::NotDirectory(data_dir));
    }

    let cache_lock = data_dir.join("client.lock");
    let mut locks = FileLocks::new();
    locks.add(&cache_lock)?;

    // FIXME: support ephemeral device signer for when the CLI
    // FIXME: is running on the same device as a GUI

    let account = if let Some(account) = account.take() {
        account
    } else {
        let account = choose_account().await?;
        let account = account.ok_or_else(|| Error::NoAccounts)?;
        account.into()
    };

    let mut owner = auth(&account, factory.clone()).await?;
    owner.initialize_search_index().await?;
    welcome(&factory)?;

    /*
    match &factory {
        ProviderFactory::Remote(remote) => {
            // Listen for change notifications
            spawn_changes_listener(
                remote.clone(),
                user.signer.clone(),
                Arc::clone(&provider),
            );
        }
        _ => {}
    }
    */

    // Prepare state for shell execution
    let user = USER.get_or_init(|| Arc::new(RwLock::new(owner)));
    cd_folder(Arc::clone(user), folder.as_ref()).await?;

    let mut rl = readline::basic_editor()?;
    loop {
        let prompt_value = {
            let owner = user.read().await;
            let account_name = owner.user().account().label();
            if let Some(current) = owner.storage().current() {
                format!("{}@{}> ", account_name, current.name())
            } else {
                format!("{}> ", account_name)
            }
        };
        let readline = rl.readline(&prompt_value);
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str())?;
                let provider = Arc::clone(user);
                if let Err(e) = exec(&line, factory.clone(), provider).await {
                    tracing::error!(target: TARGET, "{}", e);
                }
            }
            Err(e) => return Err(Error::Readline(e)),
        }
    }
}
