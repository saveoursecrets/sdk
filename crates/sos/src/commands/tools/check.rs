use crate::{
    helpers::{account::resolve_account_address, messages::success},
    Error, Result,
};
use clap::Subcommand;
use futures::{pin_mut, StreamExt};
use sos_backend::BackendTarget;
use sos_client_storage::{ClientFolderStorage, ClientStorage};
use sos_core::{AccountRef, FolderRef, Paths};
use sos_integrity::{event_integrity, vault_integrity};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print an account login folder.
    Login {
        /// Account name or identifier.
        #[clap(short, long)]
        account: AccountRef,

        /// Print more information.
        #[clap(short, long)]
        verbose: bool,
    },
    /// Print a folder vault.
    Vault {
        /// Print the header flags.
        #[clap(short, long)]
        verbose: bool,

        /// Account name or identifier.
        #[clap(short, long)]
        account: AccountRef,

        /// Folder name or identifier.
        #[clap(short, long)]
        folder: FolderRef,
    },
    /// Verify vault row checksums.
    VerifyVault {
        /// Print the checksums for each row.
        #[clap(short, long)]
        verbose: bool,

        /// Account name or identifier.
        #[clap(short, long)]
        account: AccountRef,

        /// Folder name or identifier.
        #[clap(short, long)]
        folder: FolderRef,
    },
    /// Verify event log checksums.
    VerifyEvents {
        /// Print more information.
        #[clap(short, long)]
        verbose: bool,

        /// Account name or identifier.
        #[clap(short, long)]
        account: AccountRef,

        /// Folder name or identifier.
        #[clap(short, long)]
        folder: FolderRef,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Login { account, verbose } => {
            let account_id = resolve_account_address(Some(&account)).await?;
            let paths = Paths::new_client(Paths::data_dir()?)
                .with_account_id(&account_id);
            let target = BackendTarget::from_paths(&paths).await?;
            let storage =
                ClientStorage::new_unauthenticated(target, &account_id)
                    .await?;
            let vault = storage.read_login_vault().await?;
            if verbose {
                serde_json::to_writer_pretty(std::io::stdout(), &vault)?;
            } else {
                serde_json::to_writer_pretty(
                    std::io::stdout(),
                    vault.header(),
                )?;
            }
        }
        Command::VerifyVault {
            account,
            folder,
            verbose,
        } => {
            verify_vault(account, folder, verbose).await?;
        }
        Command::Vault {
            account,
            folder,
            verbose,
        } => {
            let account_id = resolve_account_address(Some(&account)).await?;
            let paths = Paths::new_client(Paths::data_dir()?)
                .with_account_id(&account_id);
            let target = BackendTarget::from_paths(&paths).await?;
            let folders = target.list_folders(&account_id).await?;
            let folder = folders
                .iter()
                .find(|f| match &folder {
                    FolderRef::Id(id) => f.id() == id,
                    FolderRef::Name(name) => f.name() == name,
                })
                .ok_or_else(|| Error::FolderNotFound(folder.to_string()))?;

            let storage =
                ClientStorage::new_unauthenticated(target, &account_id)
                    .await?;
            let vault = storage.read_vault(folder.id()).await?;
            if verbose {
                serde_json::to_writer_pretty(std::io::stdout(), &vault)?;
            } else {
                serde_json::to_writer_pretty(
                    std::io::stdout(),
                    vault.header(),
                )?;
            }
        }
        Command::VerifyEvents {
            account,
            folder,
            verbose,
        } => {
            verify_events(account, folder, verbose).await?;
        }
    }

    Ok(())
}

/// Verify the integrity of a vault.
async fn verify_vault(
    account: AccountRef,
    folder: FolderRef,
    verbose: bool,
) -> Result<()> {
    let account_id = resolve_account_address(Some(&account)).await?;
    let paths =
        Paths::new_client(Paths::data_dir()?).with_account_id(&account_id);
    let target = BackendTarget::from_paths(&paths).await?;
    let folders = target.list_folders(&account_id).await?;
    let folder = folders
        .iter()
        .find(|f| match &folder {
            FolderRef::Id(id) => f.id() == id,
            FolderRef::Name(name) => f.name() == name,
        })
        .ok_or_else(|| Error::FolderNotFound(folder.to_string()))?;

    let stream = vault_integrity(&target, &account_id, folder.id());
    pin_mut!(stream);

    while let Some(record) = stream.next().await {
        let (_, commit) = record?;
        if verbose {
            println!("{}", commit);
        }
    }

    success("Verified");
    Ok(())
}

/// Verify the integrity of an events log file.
pub(crate) async fn verify_events(
    account: AccountRef,
    folder: FolderRef,
    verbose: bool,
) -> Result<()> {
    let account_id = resolve_account_address(Some(&account)).await?;
    let paths =
        Paths::new_client(Paths::data_dir()?).with_account_id(&account_id);
    let target = BackendTarget::from_paths(&paths).await?;
    let folders = target.list_folders(&account_id).await?;
    let folder = folders
        .iter()
        .find(|f| match &folder {
            FolderRef::Id(id) => f.id() == id,
            FolderRef::Name(name) => f.name() == name,
        })
        .ok_or_else(|| Error::FolderNotFound(folder.to_string()))?;

    let mut commits = 0;
    let stream = event_integrity(&target, &account_id, folder.id());
    pin_mut!(stream);

    while let Some(event) = stream.next().await {
        let record = event?;
        if verbose {
            println!("hash: {}", record.commit());
        }
        commits += 1;
    }

    success(format!("Verified {} commit(s)", commits));
    Ok(())
}
