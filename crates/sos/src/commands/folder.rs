use clap::Subcommand;

use human_bytes::human_bytes;
use sos_net::sdk::{
    account::{Account, FolderCreate},
    events::{EventLogExt, LogEvent},
    hex,
    identity::AccountRef,
    vault::FolderRef,
};

use crate::{
    helpers::{
        account::{cd_folder, resolve_folder, resolve_user, SHELL},
        messages::success,
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
        #[clap(short, long)]
        folder: Option<FolderRef>,
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
        #[clap(short, long)]
        folder: Option<FolderRef>,
    },
    /// Print secret keys for a folder.
    Keys {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<FolderRef>,
    },
    /// Print commits for a folder.
    Commits {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<FolderRef>,
    },
    /// Rename a folder.
    #[clap(alias = "mv")]
    Rename {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<FolderRef>,

        /// New name for the folder.
        name: String,
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
        #[clap(short, long)]
        folder: Option<FolderRef>,
    },
    /// Verify the integrity of the folder history.
    Check {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<FolderRef>,
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
        #[clap(short, long)]
        folder: Option<FolderRef>,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    let is_shell = *SHELL.lock();

    match cmd {
        Command::New { account, name, cwd } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let folder = {
                let mut owner = user.write().await;
                let owner = owner
                    .selected_account_mut()
                    .ok_or(Error::NoSelectedAccount)?;

                let existing = owner.find(|s| s.name() == name).await;
                if existing.is_some() {
                    return Err(Error::FolderExists(name));
                }

                let FolderCreate { folder, .. } =
                    owner.create_folder(name, Default::default()).await?;
                success("Folder created");
                folder
            };
            if cwd {
                let target = Some(FolderRef::Id(*folder.id()));
                cd_folder(target.as_ref()).await?;
            }
        }
        Command::Remove { account, folder } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            if summary.flags().is_default() {
                return Err(Error::NoRemoveDefaultFolder);
            }

            let is_current = {
                let owner = user.read().await;
                let owner = owner
                    .selected_account()
                    .ok_or(Error::NoSelectedAccount)?;

                if let Some(current) = owner.current_folder().await? {
                    current.id() == summary.id()
                } else {
                    false
                }
            };

            let prompt =
                format!(r#"Delete folder "{}" (y/n)? "#, summary.name());
            if read_flag(Some(&prompt))? {
                let mut owner = user.write().await;
                {
                    let owner = owner
                        .selected_account_mut()
                        .ok_or(Error::NoSelectedAccount)?;
                    owner.delete_folder(&summary).await?;
                    success("Folder deleted");
                }
                drop(owner);

                // Removing current folder so try to use
                // the default folder
                if is_current {
                    cd_folder(None).await?;
                }
            }
        }
        Command::List { account, verbose } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let owner = user.read().await;
            let owner =
                owner.selected_account().ok_or(Error::NoSelectedAccount)?;
            let folders = owner.list_folders().await?;
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
            let user = resolve_user(account.as_ref(), false).await?;
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
            let user = resolve_user(account.as_ref(), false).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            let owner = user.read().await;
            let owner =
                owner.selected_account().ok_or(Error::NoSelectedAccount)?;

            if !is_shell {
                owner.open_folder(&summary).await?;
            }

            let ids = owner.secret_ids(&summary).await?;
            for id in ids {
                println!("{}", id);
            }
        }
        Command::Commits { account, folder } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            let owner = user.read().await;
            let owner =
                owner.selected_account().ok_or(Error::NoSelectedAccount)?;
            let storage = owner.storage().await?;
            let reader = storage.read().await;
            if let Some(folder) = reader.cache().get(summary.id()) {
                let event_log = folder.event_log();
                let event_log = event_log.read().await;
                let tree = event_log.tree();
                if let Some(leaves) = tree.leaves() {
                    for leaf in &leaves {
                        println!("{}", hex::encode(leaf));
                    }
                    println!("size = {}", leaves.len());
                }
                if let Some(root) = tree.root() {
                    println!("root = {}", root);
                }
            }
        }

        Command::Rename {
            account,
            folder,
            name,
        } => {
            let user = resolve_user(account.as_ref(), false).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            let mut owner = user.write().await;
            let owner = owner
                .selected_account_mut()
                .ok_or(Error::NoSelectedAccount)?;
            owner.rename_folder(&summary, name.clone()).await?;
            success(format!("{} -> {}", summary.name(), name));
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

            let user = resolve_user(account.as_ref(), false).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            {
                let owner = user.read().await;
                let owner = owner
                    .selected_account()
                    .ok_or(Error::NoSelectedAccount)?;
                if !is_shell {
                    owner.open_folder(&summary).await?;
                }
            }

            match cmd {
                History::Compact { .. } => {
                    let summary = {
                        let owner = user.read().await;
                        let owner = owner
                            .selected_account()
                            .ok_or(Error::NoSelectedAccount)?;
                        let summary = owner
                            .current_folder()
                            .await?
                            .ok_or(Error::NoVaultSelected)?;
                        summary.clone()
                    };

                    let prompt = Some(
                        "Compaction will remove history, are you sure (y/n)? ",
                    );
                    if read_flag(prompt)? {
                        let mut owner = user.write().await;
                        let owner = owner
                            .selected_account_mut()
                            .ok_or(Error::NoSelectedAccount)?;
                        let (_, old_size, new_size) =
                            owner.compact_folder(&summary).await?;
                        println!("Old: {}", human_bytes(old_size as f64));
                        println!("New: {}", human_bytes(new_size as f64));
                    }
                }
                History::Check { .. } => {
                    let owner = user.read().await;
                    let owner = owner
                        .selected_account()
                        .ok_or(Error::NoSelectedAccount)?;
                    let summary = owner
                        .current_folder()
                        .await?
                        .ok_or(Error::NoVaultSelected)?;
                    let storage = owner.storage().await?;
                    let owner = storage.read().await;
                    owner.verify(&summary).await?;
                    success("Verified");
                }
                History::List { verbose, .. } => {
                    let owner = user.read().await;
                    let owner = owner
                        .selected_account()
                        .ok_or(Error::NoSelectedAccount)?;
                    let summary = owner
                        .current_folder()
                        .await?
                        .ok_or(Error::NoVaultSelected)?;
                    let storage = owner.storage().await?;
                    let owner = storage.read().await;
                    let records = owner.history(&summary).await?;
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
