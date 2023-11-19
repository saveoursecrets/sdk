use clap::{Parser, Subcommand};
use sos_net::sdk::{
    account::{AccountRef, UserPaths},
    hex,
    url::Url,
    vault::VaultRef,
};
use std::path::PathBuf;

use crate::{
    commands::{
        account, audit, changes, check, device, folder, secret,
        security_report::{self, SecurityReportFormat},
        shell, AccountCommand, AuditCommand, CheckCommand, DeviceCommand,
        FolderCommand, SecretCommand,
    },
    Result,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Sos {
    /// Set the account password.
    ///
    /// Used for debugging and test purposes,
    /// not available in a release build to
    /// prevent misuse (passwords appearing in
    /// shell history).
    #[cfg(any(test, debug_assertions))]
    #[clap(
        long,
        env = "SOS_PASSWORD",
        hide = true,
        hide_env = true,
        hide_env_values = true,
        hide_short_help = true,
        hide_long_help = true
    )]
    password: Option<String>,

    /// Local storage directory.
    #[clap(long, env = "SOS_DATA_DIR")]
    storage: Option<PathBuf>,

    /// Affirmative for all confirmation prompts.
    #[clap(long, env = "SOS_YES")]
    yes: bool,

    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage local accounts.
    Account {
        #[clap(subcommand)]
        cmd: AccountCommand,
    },
    /// Trusted device management
    Device {
        #[clap(subcommand)]
        cmd: DeviceCommand,
    },
    /// Inspect and modify folders.
    Folder {
        #[clap(subcommand)]
        cmd: FolderCommand,
    },
    /// Generate a security report.
    ///
    /// Inspect all passwords in an account and report
    /// passwords with an entropy score less than 3 or
    /// passwords that are breached.
    ///
    /// Use the --include-all option to include passwords
    /// that appear to be safe in the report.
    SecurityReport {
        /// Force overwrite if the file exists.
        #[clap(short, long)]
        force: bool,

        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Include all passwords.
        #[clap(short, long)]
        include_all: bool,

        /// Output format: csv or json.
        #[clap(short, long, default_value = "csv")]
        output_format: SecurityReportFormat,

        /// Write report to this file.
        file: PathBuf,
    },
    /// Create, edit and delete secrets.
    Secret {
        #[clap(subcommand)]
        cmd: SecretCommand,
    },
    /// Print and monitor audit logs.
    Audit {
        #[clap(subcommand)]
        cmd: AuditCommand,
    },

    /// Listen to changes event stream.
    Changes {
        /// Server URL.
        #[clap(short, long)]
        server: Url,

        /// Public key of the remote server.
        public_key: String,

        /// Account name or address.
        #[clap(short, long)]
        account: AccountRef,
    },
    /// Check file status and integrity.
    Check {
        #[clap(subcommand)]
        cmd: CheckCommand,
    },
    /// Interactive login shell.
    Shell {
        /// Folder name or identifier.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Account name or address.
        account: Option<AccountRef>,
    },
}

pub async fn run() -> Result<()> {
    let mut args = Sos::parse();

    if let Some(storage) = &args.storage {
        UserPaths::set_data_dir(storage.clone());
    }
    UserPaths::scaffold(args.storage).await?;

    #[cfg(any(test, debug_assertions))]
    if let Some(password) = args.password.take() {
        std::env::set_var("SOS_PASSWORD", password);
    }

    match args.cmd {
        Command::Account { cmd } => account::run(cmd).await?,
        Command::Device { cmd } => device::run(cmd).await?,
        Command::Folder { cmd } => folder::run(cmd).await?,
        Command::SecurityReport {
            account,
            force,
            output_format,
            include_all,
            file,
        } => {
            security_report::run(
                account,
                force,
                output_format,
                include_all,
                file,
            )
            .await?
        }
        Command::Secret { cmd } => secret::run(cmd).await?,
        Command::Audit { cmd } => audit::run(cmd).await?,
        Command::Changes {
            server,
            public_key,
            account,
        } => {
            let server_public_key = hex::decode(&public_key)?;
            changes::run(server, server_public_key, account).await?
        }
        Command::Check { cmd } => check::run(cmd).await?,
        Command::Shell { account, folder } => {
            shell::run(account, folder).await?
        }
    }
    Ok(())
}
