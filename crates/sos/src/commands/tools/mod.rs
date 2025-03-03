use crate::{
    helpers::{
        account::{resolve_account_address, resolve_user_with_password},
        messages::{info, success},
        readline::read_flag,
    },
    Error, Result,
};
use clap::Subcommand;
use sos_account::Account;
use sos_backend::{BackendTarget, FolderEventLog};
use sos_client_storage::{ClientAccountStorage, ClientStorage};
use sos_core::FolderRef;
use sos_core::{
    constants::EVENT_LOG_EXT,
    crypto::{AccessKey, Cipher, KeyDerivation},
    AccountRef, Paths,
};
use sos_reducers::FolderReducer;
use std::path::PathBuf;
use terminal_banner::{Banner, Padding};

mod audit;
mod authenticator;
mod check;
mod db;
mod debug;
mod events;
mod security_report;

use audit::Command as AuditCommand;
use authenticator::Command as AuthenticatorCommand;
use check::{verify_events, Command as CheckCommand};
use db::Command as DbCommand;
use debug::Command as DebugCommand;
use events::Command as EventsCommand;
use security_report::SecurityReportFormat;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print and monitor audit logs.
    Audit {
        #[clap(subcommand)]
        cmd: AuditCommand,
    },
    /// Export and import TOTP secrets.
    #[clap(alias = "auth")]
    Authenticator {
        #[clap(subcommand)]
        cmd: AuthenticatorCommand,
    },
    /// Check file status and integrity.
    Check {
        #[clap(subcommand)]
        cmd: CheckCommand,
    },
    /// Debug utilities.
    Debug {
        #[clap(subcommand)]
        cmd: DebugCommand,
    },
    /// Convert the cipher for an account.
    ConvertCipher {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Key derivation function.
        #[clap(short, long)]
        kdf: Option<KeyDerivation>,

        /// Convert to this cipher.
        cipher: Cipher,
    },
    /// Inspect event records.
    #[clap(alias = "event")]
    Events {
        #[clap(subcommand)]
        cmd: EventsCommand,
    },
    /// Repair a vault from a corresponding events file.
    RepairVault {
        /// Account name or address.
        account: AccountRef,

        /// Folder identifier.
        folder: FolderRef,
    },
    /// Generate a security report.
    ///
    /// Inspect all passwords in an account and report
    /// passwords with an entropy score less than 3 or
    /// passwords that are breached.
    SecurityReport {
        /// Force overwrite if the file exists.
        #[clap(long)]
        force: bool,

        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Include all entries.
        ///
        /// Security reports by default only include
        /// entries that fail, use this option to include
        /// entries that passed the security threshold.
        #[clap(short, long)]
        include_all: bool,

        /// Output format: csv or json.
        #[clap(short, long, default_value = "csv")]
        format: SecurityReportFormat,

        /// Write report to this file.
        file: PathBuf,
    },
    /// Backend database management tools.
    Db {
        #[clap(subcommand)]
        cmd: DbCommand,
    },
}

/// Handle sync commands.
pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Audit { cmd } => audit::run(cmd).await?,
        Command::Authenticator { cmd } => authenticator::run(cmd).await?,
        Command::Check { cmd } => check::run(cmd).await?,
        Command::Debug { cmd } => debug::run(cmd).await?,
        Command::ConvertCipher {
            account,
            cipher,
            kdf,
        } => {
            let (user, password) =
                resolve_user_with_password(account.as_ref(), false).await?;
            let mut owner = user.write().await;
            let owner = owner
                .selected_account_mut()
                .ok_or(Error::NoSelectedAccount)?;

            let banner = Banner::new()
                .padding(Padding::one())
                .text("CONVERT CIPHER".into())
                .newline()
                .text(
                  "Changing a cipher is a risky operation, be sure you understand the risks.".into())
                .newline()
                .text(
                  "* Vault and event logs will be overwritten".into())
                .text(
                  "* Event history is compacted".into())
                .text(
                  "* Sync will overwrite data on servers".into());

            let result = banner.render();
            println!("{}", result);

            let prompt =
                format!(r#"Convert to cipher "{}" (y/n)? "#, &cipher);
            if read_flag(Some(&prompt))? {
                let access_key: AccessKey = password.into();
                let conversion = owner
                    .change_cipher(&access_key, &cipher, kdf.clone())
                    .await?;
                if conversion.is_empty() {
                    info(format!(
                        "no files to convert, all folders use {} and {}",
                        cipher,
                        kdf.unwrap_or_default(),
                    ));
                } else {
                    success("cipher changed");
                }
            }
        }
        Command::Events { cmd } => events::run(cmd).await?,
        // Command::Ipc { cmd } => ipc::run(cmd).await?,
        Command::RepairVault { account, folder } => {
            let account_id = resolve_account_address(Some(&account)).await?;
            let paths = Paths::new_client(Paths::data_dir()?)
                .with_account_id(&account_id);
            let target = BackendTarget::from_paths(&paths).await?;
            let folders = target.list_folders(&account_id).await?;
            let target_folder = folders
                .iter()
                .find(|f| match &folder {
                    FolderRef::Id(id) => f.id() == id,
                    FolderRef::Name(name) => f.name() == name,
                })
                .ok_or_else(|| Error::FolderNotFound(folder.to_string()))?;

            let prompt = format!(
                "Overwrite vault file with events from {}.{} (y/n)? ",
                folder, EVENT_LOG_EXT,
            );
            if read_flag(Some(&prompt))? {
                verify_events(account, folder.clone(), false).await?;

                let event_log = FolderEventLog::new_folder(
                    target.clone(),
                    &account_id,
                    target_folder.id(),
                )
                .await?;

                let vault = FolderReducer::new()
                    .reduce(&event_log)
                    .await?
                    .build(true)
                    .await?;

                let mut storage =
                    ClientStorage::new_unauthenticated(target, &account_id)
                        .await?;
                storage.overwrite_folder_vault(&vault).await?;

                success(format!("Repaired {}", folder));
            }
        }
        Command::SecurityReport {
            account,
            force,
            format,
            include_all,
            file,
        } => {
            security_report::run(account, force, format, include_all, file)
                .await?
        }
        Command::Db { cmd } => db::run(cmd).await?,
    }
    Ok(())
}
