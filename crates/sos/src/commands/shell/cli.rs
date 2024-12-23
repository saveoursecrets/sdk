use terminal_banner::{Banner, Padding};

use sos_net::sdk::{
    account::Account, identity::AccountRef, vault::FolderRef, vfs, Paths,
};

use crate::{
    helpers::{
        account::{cd_folder, choose_account, sign_in, SHELL, USER},
        messages::fail,
        readline,
    },
    Error, Result,
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
async fn auth(account: &AccountRef) -> Result<()> {
    loop {
        match sign_in(account).await {
            Ok(_) => return Ok(()),
            Err(e) => {
                fail(e.to_string());
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

    auth(&account).await?;
    {
        let mut owner = USER.write().await;
        let user_account = owner
            .selected_account_mut()
            .ok_or(Error::NoSelectedAccount)?;
        user_account.initialize_search_index().await?;
    }
    welcome()?;

    {
        let mut is_shell = SHELL.lock();
        *is_shell = true;
    }

    // Prepare state for shell execution
    cd_folder(folder.as_ref()).await?;

    let mut rl = readline::basic_editor()?;
    loop {
        let prompt_value = {
            if let Ok(prompt) = std::env::var("SOS_PROMPT") {
                prompt
            } else {
                let owner = USER.read().await;
                let owner = owner
                    .selected_account()
                    .ok_or(Error::NoSelectedAccount)?;
                let account_name = owner.account_label().await?;
                if let Some(current) = owner.current_folder().await? {
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
                if let Err(e) = exec(&line).await {
                    fail(e.to_string());
                }
            }
            Err(e) => return Err(Error::Readline(e)),
        }
    }
}
