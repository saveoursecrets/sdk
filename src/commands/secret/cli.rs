use clap::Subcommand;

use std::{sync::Arc, borrow::Cow};

use sos_core::{
    account::AccountRef,
    search::Document,
    vault::{secret::{Secret, SecretRef}, VaultRef},
    secrecy::ExposeSecret,
};
use sos_node::client::provider::ProviderFactory;

use crate::{
    helpers::{
        account::{resolve_user, USER},
        editor,
        folder::resolve_folder,
        readline::{read_flag, read_line},
        secret::{
            add_account, add_credentials, add_file, add_note, add_page,
            print_secret, resolve_secret, read_file_secret,
        },
    },
    Error, Result,
};

use human_bytes::human_bytes;

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
    /// Update a secret.
    #[clap(alias = "set")]
    Update {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Rename a secret.
    Rename {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// New name for the secret.
        #[clap(short, long)]
        name: String,

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
                println!("Secret created ✓");
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

            let (secret_id, _) =
                resolve_secret(Arc::clone(&user), &summary, &secret)
                    .await?
                    .ok_or(Error::SecretNotAvailable(secret.clone()))?;

            let mut owner = user.write().await;
            let (data, _) = owner.read_secret(&secret_id).await?;
            print_secret(&data.meta, &data.secret)?;
        }
        Command::Update {
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

            let (secret_id, _) =
                resolve_secret(Arc::clone(&user), &summary, &secret)
                    .await?
                    .ok_or(Error::SecretNotAvailable(secret.clone()))?;

            let mut owner = user.write().await;
            let (data, _) = owner.read_secret(&secret_id).await?;

            let result = if let Secret::File {
                name, mime, buffer, ..
            } = &data.secret
            {
                if mime.starts_with("text/") {
                    editor::edit(&data.secret)?
                } else {
                    println!(
                        "Binary {} {} {}",
                        name,
                        mime,
                        human_bytes(buffer.expose_secret().len() as f64)
                    );
                    let file_path = read_line(Some("File path: "))?;
                    Cow::Owned(read_file_secret(&file_path)?)
                }
            } else {
                editor::edit(&data.secret)?
            };

            if let Cow::Owned(edited_secret) = result {
               owner 
                    .update_secret(&secret_id, data.meta, Some(edited_secret), None)
                    .await?;
                println!("Secret updated ✓");
            // If the edited result was borrowed
            // it indicates that no changes were made
            } else {
                println!("No changes detected");
            }
        }
        Command::Rename {
            account,
            folder,
            name,
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

            let (secret_id, mut meta) =
                resolve_secret(Arc::clone(&user), &summary, &secret)
                    .await?
                    .ok_or(Error::SecretNotAvailable(secret.clone()))?;
            meta.set_label(name);

            let mut owner = user.write().await;
            owner.update_secret(&secret_id, meta, None, None).await?;
            println!("Secret renamed ✓");
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

            let (secret_id, meta) =
                resolve_secret(Arc::clone(&user), &summary, &secret)
                    .await?
                    .ok_or(Error::SecretNotAvailable(secret.clone()))?;

            let prompt = format!(r#"Delete "{}" (y/n)? "#, meta.label());
            if read_flag(Some(&prompt))? {
                let mut owner = user.write().await;
                owner.delete_secret(&secret_id).await?;
                println!("Secret deleted ✓");
            }
        }
    }

    Ok(())
}
