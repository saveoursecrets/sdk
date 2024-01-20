use crate::{helpers::account::resolve_user, Error, Result};
use clap::Subcommand;
use sos_net::{
    client::{NetworkAccount, RemoteSync, SyncOptions},
    sdk::{
        account::Account,
        commit::{CommitState, CommitTree, Comparison},
        events::EventLogExt,
        identity::AccountRef,
        sync::{Origin, SyncStatus, SyncStorage},
        url::Url,
    },
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
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;
            let servers = owner.servers().await;
            if servers.is_empty() {
                return Err(Error::NoServers);
            }

            let origins = if url.is_empty() {
                vec![]
            } else {
                let origins: Vec<Origin> = url
                    .into_iter()
                    .map(|u| u.into())
                    .filter(|o| servers.contains(&o))
                    .collect();

                if origins.is_empty() {
                    return Err(Error::NoMatchServers);
                }
                origins
            };

            let options = SyncOptions { origins };
            let local_status = owner.sync_status().await?;
            let server_status = owner.server_status(&options).await;

            for (origin, maybe_status) in server_status {
                println!("[{} = {}]", origin.name(), origin.url());
                match maybe_status {
                    Ok(status) => {
                        if let Some(status) = status {
                            print_status(&*owner, &local_status, &status)
                                .await?;
                        } else {
                            println!("account does not exist, sync required");
                        }
                    }
                    Err(e) => {
                        println!("error: {}", e);
                    }
                }
            }
        }
    }
    Ok(())
}

async fn print_status(
    owner: &NetworkAccount,
    local: &SyncStatus,
    remote: &SyncStatus,
) -> Result<()> {
    {
        let log = owner.identity_log().await?;
        let log = log.read().await;
        print_commit_state(
            "👤 Identity",
            &local.identity,
            &remote.identity,
            log.tree(),
        )?;
    }

    {
        let log = owner.account_log().await?;
        let log = log.read().await;
        print_commit_state(
            "🗄  Account",
            &local.account,
            &remote.account,
            log.tree(),
        )?;
    }

    {
        let log = owner.device_log().await?;
        let log = log.read().await;
        print_commit_state(
            "📱 Device",
            &local.device,
            &remote.device,
            log.tree(),
        )?;
    }

    match (&local.files, &remote.files) {
        (Some(local_files), Some(remote_files)) => {
            let log = owner.file_log().await?;
            let log = log.read().await;
            print_commit_state(
                "📄 Files",
                local_files,
                remote_files,
                log.tree(),
            )?;
        }
        (None, Some(remote_files)) => {
            print_title("📄 Files", "pull from server");
        }
        (Some(local_files), None) => {
            print_title("📄 Files", "push to server");
        }
        _ => {}
    }

    let folders = owner.list_folders().await?;
    for folder in folders {
        let id = folder.id();
        let storage = owner.storage().await?;
        let storage = storage.read().await;
        let disc_folder = storage.cache().get(id).unwrap();
        let log = disc_folder.event_log();
        let log = log.read().await;
        if let (Some(local_folder), Some(remote_folder)) =
            (local.folders.get(id), remote.folders.get(id))
        {
            let title = format!("📁 {}", folder.name());
            print_commit_state(
                &title,
                local_folder,
                remote_folder,
                log.tree(),
            )?;
        }
    }

    Ok(())
}

fn print_title(title: &str, detail: &str) {
    println!("  {} {}", title, detail);
}

fn print_commit_state(
    title: &str,
    local: &CommitState,
    remote: &CommitState,
    local_tree: &CommitTree,
) -> Result<()> {
    let local_root = &local.1.root;
    let remote_root = &remote.1.root;
    let comparison = local_tree.compare(&remote.1)?;

    let detail = match &comparison {
        Comparison::Equal => String::from("✓"),
        Comparison::Contains(_, _) => {
            let amount = local.1.len() - remote.1.len();
            format!("{} commit(s) ahead", amount)
        }
        _ => String::from("? commit(s) behind"),
    };

    print_title(title, &detail);
    if local_root != remote_root {
        println!("     local  = {}", &local.1.root);
        println!("     remote = {}", &remote.1.root);
    }

    Ok(())
}