use std::sync::Arc;

use terminal_banner::{Banner, Padding};

use sos_net::{
    client::NetworkAccount,
    sdk::{
        account::Account, identity::AccountRef, vault::FolderRef, vfs, Paths,
    },
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
fn welcome() -> Result<()> {
    let help_info = r#"Type "help", "--help" or "-h" for command usage
Type "quit" or "q" to exit"#;
    let banner = Banner::new()
        .padding(Padding::one())
        .text(WELCOME.into())
        .text(help_info.into())
        .render();
    println!("{}", banner);
    Ok(())
}

/// Loop sign in for shell authentication.
async fn auth(account: &AccountRef) -> Result<NetworkAccount> {
    loop {
        match sign_in(account).await {
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
    mut account: Option<AccountRef>,
    folder: Option<FolderRef>,
) -> Result<()> {
    let data_dir = Paths::data_dir().map_err(|_| Error::NoCache)?;
    if !vfs::metadata(&data_dir).await?.is_dir() {
        return Err(Error::NotDirectory(data_dir));
    }

    // FIXME: support ephemeral device signer for when the CLI
    // FIXME: is running on the same device as a GUI

    let account = if let Some(account) = account.take() {
        account
    } else {
        let account = choose_account().await?;
        let account = account.ok_or_else(|| Error::NoAccounts)?;
        account.into()
    };

    let mut owner = auth(&account).await?;
    owner.initialize_search_index().await?;
    welcome()?;

    // Prepare state for shell execution
    let user = USER.get_or_init(|| Arc::new(RwLock::new(owner)));

    cd_folder(Arc::clone(user), folder.as_ref()).await?;

    let mut rl = readline::basic_editor()?;
    loop {
        let prompt_value = {
            if let Ok(prompt) = std::env::var("SOS_PROMPT") {
                prompt
            } else {
                let owner = user.read().await;
                let account_name = owner.account_label().await?;
                let storage = owner.storage().await?;
                let reader = storage.read().await;
                if let Some(current) = reader.current_folder() {
                    format!("{}@{}> ", account_name, current.name())
                } else {
                    format!("{}> ", account_name)
                }
            }
        };

        let readline = rl.readline(&prompt_value);
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str())?;
                let provider = Arc::clone(user);
                if let Err(e) = exec(&line, provider).await {
                    tracing::error!(target: TARGET, "{}", e);
                }
            }
            Err(e) => return Err(Error::Readline(e)),
        }
    }
}
