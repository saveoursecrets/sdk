use clap::Subcommand;
use std::path::PathBuf;

use sos_core::account::AccountRef;
use sos_core::vault::VaultRef;

use crate::Result;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create a folder.
    New {
        /// Name for the new folder.
        name: String,

        /// Account name or address.
        account: Option<AccountRef>,
    },

    /// Remove a folder.
    #[clap(alias = "ls")]
    Remove {
        /// Account name or address.
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
        account: Option<AccountRef>,
    },
    /// Print folder information.
    Info {
        /// Print more information.
        #[clap(short, long)]
        verbose: bool,

        /// Include system folders.
        #[clap(short, long)]
        system: bool,

        /// Account name or address.
        account: Option<AccountRef>,

        /// Folder name or id.
        folder: Option<VaultRef>,
    },
    /// Rename a folder.
    Rename {
        /// Name for the folder.
        #[clap(short, long)]
        name: String,

        /// Account name or address.
        account: Option<AccountRef>,

        /// Folder name or id.
        folder: Option<VaultRef>,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    todo!();

    //match cmd {

    /*
    Command::New { name, folder_name } => {
        local_signup(name, folder_name).await?;
    }
    Command::List { verbose } => {
        list_accounts(verbose)?;
    }
    Command::Info {
        account,
        verbose,
        system,
    } => {
        account_info(account, verbose, system).await?;
    }
    Command::Backup {
        account,
        output,
        force,
    } => {
        account_backup(account, output, force)?;
    }
    Command::Restore { input } => {
        if let Some(account) = account_restore(input).await? {
            println!("{} ({}) ✓", account.label(), account.address());
        }
    }
    Command::Rename { name, account } => {
        account_rename(account, name)?;
        println!("account renamed ✓");
    }
    */
    //}

    Ok(())
}
