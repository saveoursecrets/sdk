use clap::Subcommand;

use std::sync::Arc;

use sos_core::{
    account::AccountRef,
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
        Command::Get {
            account,
            folder,
            secret,
        } => {
            let user = resolve_user(factory, account).await?;
            let summary = resolve_folder(&user, folder)
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            // TODO: also open if the target folder is not the 
            // TODO: current shell folder
            if !is_shell {
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
