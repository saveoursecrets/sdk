use clap::Subcommand;

use std::{borrow::Cow, sync::Arc};

use sos_net::client::{
    provider::ProviderFactory,
    user::{ArchiveFilter, DocumentView},
};
use sos_sdk::{
    account::AccountRef,
    search::Document,
    secrecy::ExposeSecret,
    vault::{
        secret::{Secret, SecretRef},
        VaultRef,
    },
};

use crate::{
    helpers::{
        account::{resolve_folder, resolve_user, verify, USER},
        editor,
        readline::{read_flag, read_line},
        secret::{
            add_account, add_credentials, add_file, add_note, add_page,
            print_secret, read_file_secret, resolve_secret,
        },
    },
    Error, Result,
};

use human_bytes::human_bytes;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// List secrets.
    #[clap(alias = "ls")]
    List {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Print more information.
        #[clap(short, long)]
        verbose: bool,

        /// Show all secrets.
        #[clap(long)]
        all: bool,

        /// Show favorites only.
        #[clap(long)]
        favorites: bool,
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
    Note {
        /// Name of the secret.
        name: Option<String>,
    },
    /// Add a list of credentials.
    List {
        /// Name of the secret.
        name: Option<String>,
    },
    /// Add an account password.
    Account {
        /// Name of the secret.
        name: Option<String>,
    },
    /// Add a file.
    File {
        /// Name of the secret.
        name: Option<String>,
        /// File path.
        file: String,
    },
    /// Add a page.
    Page {
        /// Name of the secret.
        name: Option<String>,
    },
}

pub async fn run(cmd: Command, factory: ProviderFactory) -> Result<()> {
    let is_shell = USER.get().is_some();

    match cmd {
        Command::List {
            account,
            folder,
            verbose,
            all,
            favorites,
        } => {
            let user = resolve_user(account, factory, true).await?;
            let owner = user.read().await;
            let archive_folder = owner
                .storage
                .state()
                .find(|s| s.flags().is_archive())
                .cloned();

            let archive_filter = archive_folder.map(|s| ArchiveFilter {
                id: *s.id(),
                include_documents: false,
            });

            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            let mut views = vec![DocumentView::Vault(*summary.id())];

            if all {
                views = vec![DocumentView::All {
                    ignored_types: None,
                }];
            } else if let Some(folder) = &folder {
                let summary = owner
                    .storage
                    .state()
                    .find_vault(folder)
                    .cloned()
                    .ok_or(Error::VaultNotAvailable(folder.clone()))?;
                views = vec![DocumentView::Vault(*summary.id())];
            } else if favorites {
                views = vec![DocumentView::Favorites];
            }

            let documents =
                owner.index().query_view(views, archive_filter)?;
            let docs: Vec<&Document> = documents.iter().collect();
            print_documents(&docs, verbose)?;
        }
        Command::Add {
            account,
            folder,
            cmd,
        } => {
            let user = resolve_user(account, factory, true).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            if !is_shell || folder.is_some() {
                let mut owner = user.write().await;
                owner.open_folder(&summary)?;
            }

            let mut owner = user.write().await;
            let result = match cmd {
                AddCommand::Note { name } => add_note(name)?,
                AddCommand::List { name } => add_credentials(name)?,
                AddCommand::Account { name } => add_account(name)?,
                AddCommand::File { file, name } => add_file(file, name)?,
                AddCommand::Page { name } => add_page(name)?,
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
            let user = resolve_user(account, factory, true).await?;
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

            let verified = if meta.flags().must_verify() {
                verify(Arc::clone(&user)).await?
            } else {
                true
            };

            if verified {
                let mut owner = user.write().await;
                let (data, _) = owner.read_secret(&secret_id).await?;
                print_secret(&data.meta, &data.secret)?;
            }
        }
        Command::Update {
            account,
            folder,
            secret,
        } => {
            let user = resolve_user(account, factory, true).await?;
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

            let verified = if meta.flags().must_verify() {
                verify(Arc::clone(&user)).await?
            } else {
                true
            };

            if verified {
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
                        .update_secret(
                            &secret_id,
                            data.meta,
                            Some(edited_secret),
                            None,
                        )
                        .await?;
                    println!("Secret updated ✓");
                // If the edited result was borrowed
                // it indicates that no changes were made
                } else {
                    println!("No changes detected");
                }
            }
        }
        Command::Rename {
            account,
            folder,
            name,
            secret,
        } => {
            let user = resolve_user(account, factory, true).await?;
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

            let verified = if meta.flags().must_verify() {
                verify(Arc::clone(&user)).await?
            } else {
                true
            };

            if verified {
                meta.set_label(name);

                let mut owner = user.write().await;
                owner.update_secret(&secret_id, meta, None, None).await?;
                println!("Secret renamed ✓");
            }
        }
        Command::Del {
            account,
            folder,
            secret,
        } => {
            let user = resolve_user(account, factory, true).await?;
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

            let verified = if meta.flags().must_verify() {
                verify(Arc::clone(&user)).await?
            } else {
                true
            };

            if verified {
                let prompt = format!(r#"Delete "{}" (y/n)? "#, meta.label());
                if read_flag(Some(&prompt))? {
                    let mut owner = user.write().await;
                    owner.delete_secret(&secret_id).await?;
                    println!("Secret deleted ✓");
                }
            }
        }
    }

    Ok(())
}

fn print_documents(docs: &[&Document], verbose: bool) -> Result<()> {
    for doc in docs {
        let Document {
            secret_id, meta, ..
        } = doc;
        let label = meta.label();
        let short_name = meta.kind().short_name();
        print!("[{}] ", short_name);
        if verbose {
            println!("{} {}", secret_id, label);
        } else {
            println!("{}", label);
        }
    }
    Ok(())
}
