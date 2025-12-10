use crate::{
    Error, Result,
    helpers::{
        account::resolve_user,
        messages::{fail, success},
    },
};
use clap::Subcommand;
use sos_core::{AccountRef, Origin};
use url::Url;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Add a server.
    Add {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
        /// Server url.
        url: Url,
    },
    /// List servers.
    #[clap(alias = "ls")]
    List {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
    },
    /// Remove a server.
    #[clap(alias = "rm")]
    Remove {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
        /// Server url.
        url: Url,
    },
}

/// Handle server commands.
pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Add { account, url } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let mut owner = user.write().await;
            let owner = owner
                .selected_account_mut()
                .ok_or(Error::NoSelectedAccount)?;
            let origin: Origin = url.into();
            let sync_result = owner.add_server(origin.clone()).await?;

            if let Some(res) = sync_result
                && let Err(err) = res.result {
                    return Err(Error::InitialSync(err));
                }

            success(format!("Added {}", origin.url()));
        }
        Command::List { account } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;
            let owner =
                owner.selected_account().ok_or(Error::NoSelectedAccount)?;
            let servers = owner.servers().await;
            if servers.is_empty() {
                println!("No servers yet");
            } else {
                for server in &servers {
                    println!("name = {}", server.name());
                    println!("url  = {}", server.url());
                }
            }
        }
        Command::Remove { account, url } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let mut owner = user.write().await;
            let owner = owner
                .selected_account_mut()
                .ok_or(Error::NoSelectedAccount)?;
            let origin: Origin = url.into();
            let remote = owner.remove_server(&origin).await?;

            if remote.is_some() {
                success(format!("Removed {}", origin.url()));
            } else {
                fail(format!("server {} does not exist", origin.url()));
            }
        }
    }
    Ok(())
}
