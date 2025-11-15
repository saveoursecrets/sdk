use crate::{Error, Result};
use clap::Subcommand;
use colored::Colorize;
use sos_cli_helpers::messages::{info, success, warn};
use sos_core::Paths;
use sos_database::{migrations::migrate_client, open_file};
use sos_database_upgrader::{
    archive::upgrade_backup_archive, upgrade_accounts, UpgradeOptions,
};
use sos_vault::list_accounts;
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Upgrade from filesystem to SQLite database backend.
    Upgrade {
        /// Apply changes, otherwise is a dry run.
        #[clap(short, long)]
        apply_changes: bool,

        /// Keep stale files on disc.
        #[clap(short, long)]
        keep_stale_files: bool,

        /// Server accounts storage.
        #[clap(short, long)]
        server: bool,

        /// Directory for account backups.
        #[clap(short, long)]
        backup_directory: Option<PathBuf>,

        /// Root directory for the file system accounts.
        directory: PathBuf,
    },
    /// Upgrade a version 1 or 2 backup archive to version 3.
    UpgradeArchive {
        /// Input backup archive ZIP file.
        input: PathBuf,
        /// Output backup archive ZIP file.
        output: PathBuf,
    },
    /// Migrate a database file, create the file when necessary.
    ///
    /// If no specific file is given runs migrations on the
    /// database for the current documents directory.
    Migrate {
        /// Database file.
        database: Option<PathBuf>,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Upgrade {
            apply_changes,
            server,
            directory,
            keep_stale_files,
            backup_directory,
        } => {
            if !directory.is_dir() {
                return Err(Error::NotDirectory(directory));
            }

            let paths = if server {
                Paths::new_server(&directory)
            } else {
                Paths::new_client(&directory)
            };

            if !paths.identity_dir().is_dir() {
                return Err(Error::NotDirectory(
                    paths.identity_dir().to_owned(),
                ));
            }

            let accounts = list_accounts(Some(&paths)).await?;

            if !apply_changes {
                warn(
                    "dry run, use --apply-changes to perform upgrade"
                );
            }
            info(format!("found {} accounts to upgrade", accounts.len()));
            for account in &accounts {
                info(format!("{} {}", account.account_id(), account.label()));
            }

            let options = UpgradeOptions {
                dry_run: !apply_changes,
                paths,
                keep_stale_files,
                backup_directory,
                ..Default::default()
            };
            let result = upgrade_accounts(&directory, options).await?;
            serde_json::to_writer_pretty(&mut std::io::stdout(), &result)?;
        }
        Command::UpgradeArchive { input, output } => {
            upgrade_backup_archive(input, output).await?;
            success("Backup archive upgrade completed");
        }
        Command::Migrate { database } => {
            let db = if let Some(database) = database {
                database
            } else {
                let paths = Paths::new_client(Paths::data_dir()?);
                paths.database_file().to_owned()
            };
            let mut client = open_file(&db).await?;
            let report = migrate_client(&mut client).await?;
            let migrations = report.applied_migrations();
            for migration in migrations {
                println!(
                    "Migration      {} {}",
                    migration.name().green(),
                    format!("v{}", migration.version()).green(),
                );
            }
            if migrations.is_empty() {
                info("No migrations to apply");
            }
        }
    }
    Ok(())
}
