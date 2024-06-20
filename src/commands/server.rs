use crate::{
    helpers::{
        account::resolve_user,
        messages::{fail, success},
    },
    Error, Result,
};
use clap::Subcommand;
use sos_net::{
    client::RemoteSync,
    protocol::{Origin, SyncOptions},
    sdk::{identity::AccountRef, url::Url},
};

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
            let origin: Origin = url.into();
            owner.add_server(origin.clone()).await?;
            let options = SyncOptions {
                origins: vec![origin.clone()],
                ..Default::default()
            };

            let sync_error = owner.sync_with_options(&options).await;
            if let Some(err) = sync_error {
                owner.remove_server(&origin).await?;
                return Err(Error::InitialSync(err));
            } else {
                success(format!("Added {}", origin.url()));
            }
        }
        Command::List { account } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;
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
