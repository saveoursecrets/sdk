use clap::Subcommand;

use sos_core::{
    hex,
    account::{AccountRef, DelegatedPassphrase},
    vault::{Summary, VaultRef},
};
use sos_node::client::provider::ProviderFactory;

use crate::{
    helpers::{
        account::{resolve_user, Owner, USER},
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
        /*
        /// Print more information.
        #[clap(short, long)]
        verbose: bool,
        */

        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        folder: Option<VaultRef>,
    },
    /// Print secret keys for a folder.
    Keys {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        folder: Option<VaultRef>,
    },

    /// Print commit tree leaves for a folder.
    Commits {
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
    let is_shell = USER.get().is_some();

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
            let prompt =
                format!(r#"Delete folder "{}" (y/n)? "#, summary.name(),);
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
            //verbose,
        } => {
            let user = resolve_user(factory, account).await?;
            let summary = resolve_folder(&user, folder)
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;
            println!("{}", summary);
        }
        Command::Keys {
            account,
            folder,
        } => {
            let user = resolve_user(factory, account).await?;
            let summary = resolve_folder(&user, folder)
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            let mut writer = user.write().await;

            if !is_shell {
                let passphrase = DelegatedPassphrase::find_vault_passphrase(
                    writer.user.identity().keeper(),
                    summary.id(),
                )?;
                writer.storage.open_vault(&summary, passphrase, None)?;
            }

            let keeper =
                writer.storage.current().ok_or(Error::NoVaultSelected)?;
            for uuid in keeper.vault().keys() {
                println!("{}", uuid);
            }
        }
        Command::Commits {
            account,
            folder,
        } => {
            let user = resolve_user(factory, account).await?;
            let summary = resolve_folder(&user, folder)
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;
            
            let reader = user.read().await;
            if let Some(tree) = reader.storage.commit_tree(&summary) {
                if let Some(leaves) = tree.leaves() {
                    for leaf in &leaves {
                        println!("{}", hex::encode(leaf));
                    }
                    println!("size = {}", leaves.len());
                }
                if let Some(root) = tree.root_hex() {
                    println!("root = {}", root);
                }
            }
        },

        Command::Rename {
            account,
            folder,
            name,
        } => {
            let user = resolve_user(factory, account).await?;
            let summary = resolve_folder(&user, folder)
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;
            
            let mut writer = user.write().await;
            writer.rename_folder(&summary, name.clone()).await?;
            println!("{} -> {} ✓", summary.name(), name);
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
        if let Some(owner) = USER.get() {
            let reader = owner.read().await;
            let keeper =
                reader.storage.current().ok_or(Error::NoVaultSelected)?;
            Ok(Some(keeper.summary().clone()))
        } else {
            Ok(reader.storage.state().find_default_vault().cloned())
        }
    }
}
