use crate::{helpers::account::resolve_user, Error, Result};
use clap::Subcommand;
use sos_net::{
    client::{RemoteSync, SyncOptions},
    sdk::{identity::AccountRef, sync::Origin, url::Url},
};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Sync with all remote origins.
    All {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Server url(s).
        url: Vec<Url>,
    },
    /// Compare local and remote status.
    Status {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Server url(s).
        url: Vec<Url>,
    },
}

/// Handle sync commands.
pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::All { account, url } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;
            let servers = owner.servers().await;
            if servers.is_empty() {
                return Err(Error::NoServers);
            }

            if url.is_empty() {
                let sync_error = owner.sync().await;
                if sync_error.is_some() {
                    return Err(Error::SyncFail);
                }
            } else {
                let origins: Vec<Origin> = url
                    .into_iter()
                    .map(|u| u.into())
                    .filter(|o| servers.contains(&o))
                    .collect();

                if origins.is_empty() {
                    return Err(Error::NoMatchServers);
                }

                let options = SyncOptions { origins };
                let sync_error = owner.sync_with_options(&options).await;
                if sync_error.is_some() {
                    return Err(Error::SyncFail);
                }
            }
            println!("Synced ✓");
        }
        Command::Status { account, url } => {
            todo!("sync status for remote origins");
        }
    }
    Ok(())
}
