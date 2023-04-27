use clap::Subcommand;

use human_bytes::human_bytes;
use sos_core::{
    account::{AccountRef, DelegatedPassphrase},
    hex,
    vault::VaultRef,
};
use sos_node::client::provider::ProviderFactory;

use crate::{
    helpers::{
        account::{resolve_user, USER},
        folder::resolve_folder,
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
    /// Manage the history for a folder.
    History {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        folder: Option<VaultRef>,

        #[clap(subcommand)]
        cmd: History,
    },
}

/// Folder history.
#[derive(Subcommand, Debug)]
pub enum History {
    /// Compact the history for this folder.
    Compact,
    /// Verify the integrity of the folder history.
    Check,
    /// List history events.
    #[clap(alias = "ls")]
    List {
        /// Print more information.
        #[clap(short, long)]
        verbose: bool,
    },
}

pub async fn run(cmd: Command, factory: ProviderFactory) -> Result<()> {
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
        Command::Keys { account, folder } => {
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
        Command::Commits { account, folder } => {
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
        }

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

        Command::History {
            account,
            folder,
            cmd,
        } => {
            let user = resolve_user(factory, account).await?;
            let summary = resolve_folder(&user, folder)
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            {
                let mut writer = user.write().await;
                if !is_shell {
                    let passphrase =
                        DelegatedPassphrase::find_vault_passphrase(
                            writer.user.identity().keeper(),
                            summary.id(),
                        )?;
                    writer.storage.open_vault(&summary, passphrase, None)?;
                }
            }

            match cmd {
                History::Compact => {
                    let reader = user.read().await;
                    let keeper = reader
                        .storage
                        .current()
                        .ok_or(Error::NoVaultSelected)?;
                    let summary = keeper.summary().clone();
                    drop(reader);

                    let prompt = Some(
                        "Compaction will remove history, are you sure (y/n)? ",
                    );
                    if read_flag(prompt)? {
                        let mut writer = user.write().await;
                        let (old_size, new_size) =
                            writer.storage.compact(&summary).await?;
                        println!("Old: {}", human_bytes(old_size as f64));
                        println!("New: {}", human_bytes(new_size as f64));
                    }
                }
                History::Check => {
                    let reader = user.read().await;
                    let keeper = reader
                        .storage
                        .current()
                        .ok_or(Error::NoVaultSelected)?;
                    reader.storage.verify(keeper.summary())?;
                    println!("Verified ✓");
                }
                History::List { verbose } => {
                    let reader = user.read().await;
                    let keeper = reader
                        .storage
                        .current()
                        .ok_or(Error::NoVaultSelected)?;
                    let records = reader.storage.history(keeper.summary())?;
                    for (commit, time, event) in records {
                        print!("{} {} ", event.event_kind(), time);
                        if verbose {
                            println!("{}", commit);
                        } else {
                            println!();
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
