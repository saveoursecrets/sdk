use crate::{
    helpers::{
        account::resolve_account,
        account::resolve_user_with_password,
        messages::{fail, info, success},
        readline::read_flag,
    },
    Error, Result,
};
use clap::Subcommand;
use sos_net::sdk::{
    account::Account,
    constants::EVENT_LOG_EXT,
    crypto::{AccessKey, Cipher, KeyDerivation},
    encode,
    events::{FolderEventLog, FolderReducer},
    identity::AccountRef,
    vault::VaultId,
    vfs, Paths,
};
use std::path::PathBuf;
use terminal_banner::{Banner, Padding};

mod audit;
mod authenticator;
mod check;
mod events;
mod security_report;

use audit::Command as AuditCommand;
use authenticator::Command as AuthenticatorCommand;
use check::{verify_events, Command as CheckCommand};
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
        folder: VaultId,
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
}

/// Handle sync commands.
pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Audit { cmd } => audit::run(cmd).await?,
        Command::Authenticator { cmd } => authenticator::run(cmd).await?,
        Command::Check { cmd } => check::run(cmd).await?,
        Command::ConvertCipher {
            account,
            cipher,
            kdf,
        } => {
            let (user, password) =
                resolve_user_with_password(account.as_ref(), false).await?;
            let mut owner = user.write().await;

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
        Command::RepairVault { account, folder } => {
            let account = resolve_account(Some(&account))
                .await
                .ok_or(Error::NoAccount(account.to_string()))?;

            match account {
                AccountRef::Address(address) => {
                    let paths =
                        Paths::new(Paths::data_dir()?, address.to_string());
                    let events_file = paths.event_log_path(&folder);
                    let vault_file = paths.vault_path(&folder);

                    if !vfs::try_exists(&events_file).await? {
                        return Err(Error::NotFile(events_file));
                    }

                    if !vfs::try_exists(&vault_file).await? {
                        return Err(Error::NotFile(vault_file));
                    }

                    let prompt = format!(
                        "Overwrite vault file with events from {}.{} (y/n)? ",
                        folder, EVENT_LOG_EXT,
                    );
                    if read_flag(Some(&prompt))? {
                        verify_events(events_file.clone(), false).await?;

                        let event_log =
                            FolderEventLog::new(&events_file).await?;

                        let vault = FolderReducer::new()
                            .reduce(&event_log)
                            .await?
                            .build(true)
                            .await?;

                        let buffer = encode(&vault).await?;
                        vfs::write(vault_file, buffer).await?;

                        success(format!("Repaired {}", folder));
                    }
                }
                _ => fail("unable to locate account"),
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
    }
    Ok(())
}
