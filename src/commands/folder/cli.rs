use clap::Subcommand;

use sos_core::{
    account::AccountRef,
    vault::{Summary, VaultRef},
};
use sos_node::client::provider::ProviderFactory;

use crate::{
    helpers::{
        account::{resolve_user, Owner},
        readline::read_flag,
    },
    Error, Result,
};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a folder.
    New {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Name for the new folder.
        name: String,
    },
    /// Remove a folder.
    #[clap(alias = "rm")]
    Remove {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        folder: Option<VaultRef>,
    },

    /// List folders.
    #[clap(alias = "ls")]
    List {
        /// Print more information.
        #[clap(short, long)]
        verbose: bool,

        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
    },
    /// Print folder information.
    Info {
        /// Print more information.
        #[clap(short, long)]
        verbose: bool,

        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        folder: Option<VaultRef>,
    },
    /// Rename a folder.
    #[clap(alias = "mv")]
    Rename {
        /// Name for the folder.
        #[clap(short, long)]
        name: String,

        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        folder: Option<VaultRef>,
    },
}

pub async fn run(factory: ProviderFactory, cmd: Command) -> Result<()> {
    match cmd {
        Command::New { account, name } => {
            let user = resolve_user(factory, account).await?;
            let mut writer = user.write().await;
            let summary = writer.create_folder(name).await?;
            println!("{} created ✓", summary.name());
        }
        Command::Remove { account, folder } => {
            let user = resolve_user(factory, account).await?;
            let summary = resolve_folder(&user, folder)
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;
            let prompt = format!(
                r#"Delete folder "{}" (y/n)? "#,
                summary.name(),
            );
            if read_flag(Some(&prompt))? {
                let mut writer = user.write().await;
                writer.remove_folder(&summary).await?;
                println!("{} removed ✓", summary.name());
            }
        }
        Command::List { account, verbose } => {
            let user = resolve_user(factory, account).await?;
            let mut writer = user.write().await;
            let folders = writer.storage.load_vaults().await?;
            for summary in folders {
                if verbose {
                    println!("{} {}", summary.id(), summary.name());
                } else {
                    println!("{}", summary.name());
                }
            }
        }
        Command::Info {
            account,
            folder,
            verbose,
        } => {
            todo!()
        }
        Command::Rename {
            account,
            folder,
            name,
        } => {
            todo!()
        }
    }

    Ok(())
}

async fn resolve_folder(
    owner: &Owner,
    folder: Option<VaultRef>,
) -> Result<Option<Summary>> {
    let reader = owner.read().await;
    if let Some(vault) = folder {
        Ok(Some(
            reader
                .storage
                .state()
                .find_vault(&vault)
                .cloned()
                .ok_or(Error::VaultNotAvailable(vault))?,
        ))
    } else {
        Ok(reader.storage.state().find_default_vault().cloned())
    }
}
