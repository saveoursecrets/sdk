use clap::Subcommand;

use std::sync::Arc;

use sos_core::{
    account::AccountRef,
    search::Document,
    vault::{secret::SecretRef, VaultRef},
};
use sos_node::client::provider::ProviderFactory;

use crate::{
    helpers::{
        account::{resolve_user, USER},
        folder::resolve_folder,
        secret::{find_secret_meta, print_secret},
    },
    Error, Result,
};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// List secrets in a folder.
    #[clap(alias = "ls")]
    List {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Print more information
        #[clap(short, long)]
        verbose: bool,
    },
    /// Print a secret.
    Get {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Secret name or identifier.
        secret: SecretRef,
    },
}

pub async fn run(cmd: Command, factory: ProviderFactory) -> Result<()> {
    let is_shell = USER.get().is_some();

    match cmd {
        Command::List {
            account,
            folder,
            verbose,
        } => {
            let user = resolve_user(factory, account).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            if !is_shell || folder.is_some() {
                let mut owner = user.write().await;
                owner.open_folder(&summary)?;
            }

            let owner = user.read().await;
            let keeper = owner.storage.current().ok_or(
                Error::NoVaultSelected)?;
            let index = keeper.index();
            let index_reader = index.read();
            let meta = index_reader.values();
            for doc in meta {
                let Document {
                    secret_id, meta, ..
                } = doc;
                let label = meta.label();
                let short_name = meta.short_name();
                print!("[{}] ", short_name);
                if verbose {
                    println!("{} {}", secret_id, label);
                } else {
                    println!("{}", label);
                }
            }

        }
        Command::Get {
            account,
            folder,
            secret,
        } => {
            let user = resolve_user(factory, account).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            if !is_shell || folder.is_some() {
                let mut owner = user.write().await;
                owner.open_folder(&summary)?;
            }

            let (uuid, _) = find_secret_meta(Arc::clone(&user), &secret)
                .await?
                .ok_or(Error::SecretNotAvailable(secret.clone()))?;

            let mut owner = user.write().await;
            let (meta, secret, _) = owner.storage.read_secret(&uuid).await?;
            print_secret(&meta, &secret)?;
        }
    }

    Ok(())
}
