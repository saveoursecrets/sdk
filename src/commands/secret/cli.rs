use clap::Subcommand;

use std::sync::Arc;

use sos_core::{
    account::AccountRef,
    search::Document,
    vault::{secret::SecretRef, VaultRef},
};
use sos_node::client::provider::ProviderFactory;

use crate::{
    helpers::{
        account::{resolve_user, USER},
        folder::resolve_folder,
        readline::read_flag,
        secret::{
            add_account, add_credentials, add_file, add_note, add_page,
            print_secret, resolve_secret,
        },
    },
    Error, Result,
};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// List secrets in a folder.
    #[clap(alias = "ls")]
    List {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Print more information
        #[clap(short, long)]
        verbose: bool,
    },
    /// Add a secret.
    Add {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        #[clap(subcommand)]
        cmd: AddCommand,
    },
    /// Print a secret.
    Get {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Delete a secret.
    Del {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Secret name or identifier.
        secret: SecretRef,
    },
}

#[derive(Subcommand, Debug)]
pub enum AddCommand {
    /// Add a note.
    Note { label: Option<String> },
    /// Add a list of credentials.
    List { label: Option<String> },
    /// Add an account password.
    Account { label: Option<String> },
    /// Add a file.
    File { path: String, label: Option<String> },
    /// Add a page.
    Page { label: Option<String> },
}

pub async fn run(cmd: Command, factory: ProviderFactory) -> Result<()> {
    let is_shell = USER.get().is_some();

    match cmd {
        Command::List {
            account,
            folder,
            verbose,
        } => {
            let user = resolve_user(factory, account).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            if !is_shell || folder.is_some() {
                let mut owner = user.write().await;
                owner.open_folder(&summary)?;
            }

            let owner = user.read().await;
            let keeper =
                owner.storage.current().ok_or(Error::NoVaultSelected)?;
            let index = keeper.index();
            let index_reader = index.read();
            let meta = index_reader.values();
            for doc in meta {
                let Document {
                    secret_id, meta, ..
                } = doc;
                let label = meta.label();
                let short_name = meta.short_name();
                print!("[{}] ", short_name);
                if verbose {
                    println!("{} {}", secret_id, label);
                } else {
                    println!("{}", label);
                }
            }
        }
        Command::Add {
            account,
            folder,
            cmd,
        } => {
            let user = resolve_user(factory, account).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            if !is_shell || folder.is_some() {
                let mut owner = user.write().await;
                owner.open_folder(&summary)?;
            }

            let mut owner = user.write().await;
            let result = match cmd {
                AddCommand::Note { label } => add_note(label)?,
                AddCommand::List { label } => add_credentials(label)?,
                AddCommand::Account { label } => add_account(label)?,
                AddCommand::File { path, label } => add_file(path, label)?,
                AddCommand::Page { label } => add_page(label)?,
            };

            if let Some((meta, secret)) = result {
                owner.create_secret(meta, secret).await?;
                /*
                maybe_conflict(Arc::clone(&state), || async move {
                    let mut writer = state.write().await;
                    writer.storage.create_secret(meta, secret).await?;
                    Ok(())
                })
                .await
                */
            }
        }
        Command::Get {
            account,
            folder,
            secret,
        } => {
            let user = resolve_user(factory, account).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            if !is_shell || folder.is_some() {
                let mut owner = user.write().await;
                owner.open_folder(&summary)?;
            }

            let (uuid, _) =
                resolve_secret(Arc::clone(&user), &summary, &secret)
                    .await?
                    .ok_or(Error::SecretNotAvailable(secret.clone()))?;

            let mut owner = user.write().await;
            let (data, _) = owner.read_secret(&uuid).await?;
            print_secret(&data.meta, &data.secret)?;
        }

        Command::Del {
            account,
            folder,
            secret,
        } => {
            let user = resolve_user(factory, account).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            if !is_shell || folder.is_some() {
                let mut owner = user.write().await;
                owner.open_folder(&summary)?;
            }

            let (uuid, meta) =
                resolve_secret(Arc::clone(&user), &summary, &secret)
                    .await?
                    .ok_or(Error::SecretNotAvailable(secret.clone()))?;

            let prompt = format!(r#"Delete "{}" (y/n)? "#, meta.label());
            if read_flag(Some(&prompt))? {
                let mut owner = user.write().await;
                owner.delete_secret(&uuid).await?;
                println!("Secret deleted ✓");
            }
        }
    }

    Ok(())
}
