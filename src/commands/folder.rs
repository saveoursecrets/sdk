use clap::Subcommand;

use human_bytes::human_bytes;
use sos_net::client::provider::ProviderFactory;
use sos_sdk::{
    account::{AccountRef, DelegatedPassphrase},
    hex,
    vault::VaultRef,
};

use crate::{
    helpers::{
        account::{cd_folder, resolve_folder, resolve_user, USER},
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

        /// Set this folder as current working directory.
        #[clap(long)]
        cwd: bool,

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
    /// Print secret keys for a folder.
    Keys {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        folder: Option<VaultRef>,
    },
    /// Print commits for a folder.
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
        #[clap(subcommand)]
        cmd: History,
    },
}

/// Folder history.
#[derive(Subcommand, Debug)]
pub enum History {
    /// Compact the history for this folder.
    Compact {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        folder: Option<VaultRef>,
    },
    /// Verify the integrity of the folder history.
    Check {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        folder: Option<VaultRef>,
    },
    /// List history events.
    #[clap(alias = "ls")]
    List {
        /// Print more information.
        #[clap(short, long)]
        verbose: bool,

        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        folder: Option<VaultRef>,
    },
}

pub async fn run(cmd: Command, factory: ProviderFactory) -> Result<()> {
    let is_shell = USER.get().is_some();

    match cmd {
        Command::New { account, name, cwd } => {
            let user = resolve_user(account.as_ref(), factory, false).await?;
            let mut writer = user.write().await;
            let summary = writer.create_folder(name).await?;
            println!("{} created ✓", summary.name());
            drop(writer);
            if cwd {
                let target = Some(VaultRef::Id(*summary.id()));
                cd_folder(user, target.as_ref()).await?;
            }
        }
        Command::Remove { account, folder } => {
            let user = resolve_user(account.as_ref(), factory, false).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            if summary.flags().is_default() {
                return Err(Error::NoRemoveDefaultFolder);
            }

            let mut owner = user.write().await;
            let is_current = if let Some(current) = owner.storage.current() {
                current.id() == summary.id()
            } else {
                false
            };

            let prompt =
                format!(r#"Delete folder "{}" (y/n)? "#, summary.name());
            if read_flag(Some(&prompt))? {
                owner.remove_folder(&summary).await?;
                println!("{} removed ✓", summary.name());

                drop(owner);
                // Removing current folder so try to use
                // the default folder
                if is_current {
                    cd_folder(user, None).await?;
                }
            }
        }
        Command::List { account, verbose } => {
            let user = resolve_user(account.as_ref(), factory, false).await?;
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
            let user = resolve_user(account.as_ref(), factory, false).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;
            if verbose {
                println!("{}", summary);
            } else {
                println!("{}", summary.id());
            }
        }
        Command::Keys { account, folder } => {
            let user = resolve_user(account.as_ref(), factory, false).await?;
            let summary = resolve_folder(&user, folder.as_ref())
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
            let user = resolve_user(account.as_ref(), factory, false).await?;
            let summary = resolve_folder(&user, folder.as_ref())
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
            let user = resolve_user(account.as_ref(), factory, false).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            let mut writer = user.write().await;
            writer.rename_folder(&summary, name.clone()).await?;
            println!("{} -> {} ✓", summary.name(), name);
        }

        Command::History { cmd } => {
            let (account, folder) = match &cmd {
                History::Compact { account, folder } => {
                    (account.clone(), folder)
                }
                History::Check { account, folder } => {
                    (account.clone(), folder)
                }
                History::List {
                    account, folder, ..
                } => (account.clone(), folder),
            };

            let user = resolve_user(account.as_ref(), factory, false).await?;
            let summary = resolve_folder(&user, folder.as_ref())
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
                History::Compact { .. } => {
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
                History::Check { .. } => {
                    let reader = user.read().await;
                    let keeper = reader
                        .storage
                        .current()
                        .ok_or(Error::NoVaultSelected)?;
                    reader.storage.verify(keeper.summary())?;
                    println!("Verified ✓");
                }
                History::List { verbose, .. } => {
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
