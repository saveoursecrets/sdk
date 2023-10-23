use clap::{Parser, Subcommand};
use sos_net::{
    client::provider::ProviderFactory,
    sdk::{
        account::AccountRef, hex, storage::AppPaths, url::Url, vault::VaultRef,
    },
};
use std::path::PathBuf;

use crate::{
    commands::{
        account, audit, changes, check, device, folder, generate_keypair,
        security_report,
        secret, shell, AccountCommand, AuditCommand, CheckCommand,
        DeviceCommand, FolderCommand, SecretCommand,
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

    /// Storage provider factory.
    #[clap(long, env = "SOS_PROVIDER")]
    provider: Option<ProviderFactory>,

    /// Local storage directory.
    #[clap(long, env = "SOS_CACHE")]
    cache: Option<PathBuf>,

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
    /// Generate PEM-encoded noise protocol keypair.
    Keypair {
        /// Force overwrite if the file exists.
        #[clap(short, long)]
        force: bool,

        /// Write hex-encoded public key to a file.
        #[clap(long)]
        public_key: Option<PathBuf>,

        /// Write keypair to this file.
        file: PathBuf,
    },
    /// Generate a security report.
    SecurityReport {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
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
    let factory = args.provider.unwrap_or_default();

    if let Some(cache) = args.cache.take() {
        AppPaths::set_data_dir(cache);
    }
    AppPaths::scaffold().await?;

    #[cfg(any(test, debug_assertions))]
    if let Some(password) = args.password.take() {
        std::env::set_var("SOS_PASSWORD", password);
    }

    match args.cmd {
        Command::Account { cmd } => account::run(cmd, factory).await?,
        Command::Device { cmd } => device::run(cmd, factory).await?,
        Command::Folder { cmd } => folder::run(cmd, factory).await?,
        Command::Keypair {
            file,
            force,
            public_key,
        } => generate_keypair::run(file, force, public_key).await?,
        Command::SecurityReport {
            account,
        } => security_report::run(account, Default::default(), factory).await?,
        Command::Secret { cmd } => secret::run(cmd, factory).await?,
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
            shell::run(factory, account, folder).await?
        }
    }
    Ok(())
}
