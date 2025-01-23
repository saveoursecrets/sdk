use crate::{Error, Result};
use clap::Subcommand;
use sos_cli_helpers::messages::info;
use sos_core::Paths;
use sos_database::importer::UpgradeOptions;
use sos_vault::list_accounts;
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Upgrade from filesystem to SQLite database backend.
    Upgrade {
        /// Keep stale files on disc.
        #[clap(short, long)]
        keep_stale_files: bool,

        /// Server accounts storage.
        #[clap(short, long)]
        server: bool,

        /// Root directory for the file system accounts.
        directory: PathBuf,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Upgrade {
            server,
            directory,
            keep_stale_files,
        } => {
            if !directory.is_dir() {
                return Err(Error::NotDirectory(directory));
            }

            let paths = if server {
                Paths::new_global_server(directory)
            } else {
                Paths::new_global(directory)
            };

            if !paths.identity_dir().is_dir() {
                return Err(Error::NotDirectory(
                    paths.identity_dir().to_owned(),
                ));
            }

            let accounts = list_accounts(Some(&paths)).await?;

            info(format!("found {} accounts to upgrade", accounts.len()));
            for account in &accounts {
                info(format!("{} {}", account.account_id(), account.label()));
            }

            let options = UpgradeOptions { keep_stale_files };
            // println!("{:#?}", accounts);
        }
    }
    Ok(())
}
