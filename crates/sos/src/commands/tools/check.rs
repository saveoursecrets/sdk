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
    /// Dump information about the account login folder.
    Login {
        /// Account name or identifier.
        #[clap(short, long)]
        account: AccountRef,
    },
    /// Verify vault row checksums.
    Vault {
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
    /// Print a vault file header.
    Header {
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
    /// Print the vault keys.
    Keys {
        /// Account name or identifier.
        #[clap(short, long)]
        account: AccountRef,

        /// Folder name or identifier.
        #[clap(short, long)]
        folder: FolderRef,
    },
    /// Verify event log checksums.
    Events {
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
        Command::Login { account } => {
            let account_id = resolve_account_address(Some(&account)).await?;
            let paths = Paths::new_client(Paths::data_dir()?)
                .with_account_id(&account_id);
            let target = BackendTarget::from_paths(&paths).await?;
            let storage =
                ClientStorage::new_unauthenticated(target, &account_id)
                    .await?;
            let login_folder = storage.read_login_vault().await?;
            println!("{:#?}", login_folder.header());
        }
        Command::Vault {
            account,
            folder,
            verbose,
        } => {
            verify_vault(account, folder, verbose).await?;
        }
        Command::Header {
            account,
            folder,
            verbose,
        } => header(account, folder, verbose).await?,
        Command::Keys { account, folder } => keys(account, folder).await?,
        Command::Events {
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

/// Print a vault header.
pub async fn header(
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

    let storage =
        ClientStorage::new_unauthenticated(target, &account_id).await?;
    let vault = storage.read_vault(folder.id()).await?;
    let header = vault.header();

    // let header = Header::read_header_file(&vault).await?;
    println!("{}", header);
    if verbose {
        let mut details = Vec::new();
        details.push(("identity", header.flags().is_identity()));
        details.push(("system", header.flags().is_system()));
        details.push(("default", header.flags().is_default()));
        details.push(("archive", header.flags().is_archive()));
        details.push(("device", header.flags().is_device()));
        details.push(("contact", header.flags().is_contact()));
        details.push(("authenticator", header.flags().is_authenticator()));
        details.push(("sync_disabled", header.flags().is_sync_disabled()));
        details.push(("local", header.flags().is_local()));
        details.push(("shared", header.flags().is_shared()));

        let details =
            details.into_iter().filter(|(_, v)| *v).collect::<Vec<_>>();

        let mut len = 0;
        for (k, _) in &details {
            len = std::cmp::max(len, k.len());
        }

        for (name, value) in details {
            if value {
                let padding = " ".repeat(len - name.len() + 2);
                let name = format!("{}{}", padding, name);
                println!("{}: {}", name, value);
            }
        }
    }
    Ok(())
}

/// Print the vault keys.
pub async fn keys(account: AccountRef, folder: FolderRef) -> Result<()> {
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

    let storage =
        ClientStorage::new_unauthenticated(target, &account_id).await?;
    let vault = storage.read_vault(folder.id()).await?;

    for id in vault.keys() {
        println!("{}", id);
    }

    Ok(())
}
