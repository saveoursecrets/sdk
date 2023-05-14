use clap::Subcommand;

use std::{borrow::Cow, sync::Arc};

use terminal_banner::{Banner, Padding};
use tokio::sync::RwLock;

use sos_net::client::{
    provider::ProviderFactory,
    user::{ArchiveFilter, DocumentView, UserStorage},
};
use sos_sdk::{
    account::AccountRef,
    search::Document,
    secrecy::ExposeSecret,
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRef},
        Summary, VaultRef,
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
    /// Print secret meta data.
    Info {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Print debug representation.
        #[clap(short, long)]
        debug: bool,

        /// Print as JSON.
        #[clap(short, long)]
        json: bool,

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
    /// Toggle favorite flag.
    #[clap(alias = "fav")]
    Favorite {
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
        /// Comma separated tags.
        #[clap(short, long)]
        tags: Option<String>,

        /// Name of the secret.
        name: Option<String>,
    },
    /// Add a list of credentials.
    List {
        /// Comma separated tags.
        #[clap(short, long)]
        tags: Option<String>,

        /// Name of the secret.
        name: Option<String>,
    },
    /// Add an account password.
    Account {
        /// Comma separated tags.
        #[clap(short, long)]
        tags: Option<String>,

        /// Name of the secret.
        name: Option<String>,
    },
    /// Add a file.
    File {
        /// Comma separated tags.
        #[clap(short, long)]
        tags: Option<String>,

        /// Name of the secret.
        name: Option<String>,

        /// File path.
        file: String,
    },
    /// Add a page.
    Page {
        /// Comma separated tags.
        #[clap(short, long)]
        tags: Option<String>,

        /// Name of the secret.
        name: Option<String>,
    },
}

struct ResolvedSecret {
    user: Arc<RwLock<UserStorage>>,
    secret_id: SecretId,
    meta: SecretMeta,
    verified: bool,
    summary: Summary,
}

async fn resolve_verify(
    factory: ProviderFactory,
    account: Option<AccountRef>,
    folder: Option<VaultRef>,
    secret: SecretRef,
) -> Result<ResolvedSecret> {
    let is_shell = USER.get().is_some();

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

    Ok(ResolvedSecret {
        user,
        secret_id,
        meta,
        summary,
        verified,
    })
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
                AddCommand::Note { name, tags } => add_note(name, tags)?,
                AddCommand::List { name, tags } => {
                    add_credentials(name, tags)?
                }
                AddCommand::Account { name, tags } => {
                    add_account(name, tags)?
                }
                AddCommand::File { file, name, tags } => {
                    add_file(file, name, tags)?
                }
                AddCommand::Page { name, tags } => add_page(name, tags)?,
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
            let resolved =
                resolve_verify(factory, account, folder, secret).await?;
            if resolved.verified {
                let mut owner = resolved.user.write().await;
                let (data, _) =
                    owner.read_secret(&resolved.secret_id).await?;
                print_secret(&data.meta, &data.secret)?;
            }
        }
        Command::Info {
            account,
            folder,
            secret,
            debug,
            json,
        } => {
            let resolved =
                resolve_verify(factory, account, folder, secret).await?;
            if resolved.verified {
                let meta = resolved.meta;

                if debug {
                    println!("{:#?}", meta);
                } else if json {
                    serde_json::to_writer_pretty(
                        &mut std::io::stdout(),
                        &meta,
                    )?;
                    println!();
                } else {
                    let banner = Banner::new()
                        .padding(Padding::one())
                        .text(Cow::Owned(meta.to_string()));
                    let result = banner.render();
                    println!("{}", result);
                }
            }
        }
        Command::Update {
            account,
            folder,
            secret,
        } => {
            let resolved =
                resolve_verify(factory, account, folder, secret).await?;
            if resolved.verified {
                let mut owner = resolved.user.write().await;
                let (data, _) =
                    owner.read_secret(&resolved.secret_id).await?;

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
                            &resolved.secret_id,
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
        Command::Favorite {
            account,
            folder,
            secret,
        } => {
            let mut resolved =
                resolve_verify(factory, account, folder, secret).await?;
            if resolved.verified {
                let value = !resolved.meta.favorite();
                resolved.meta.set_favorite(value);

                let mut owner = resolved.user.write().await;
                owner
                    .update_secret(
                        &resolved.secret_id,
                        resolved.meta,
                        None,
                        None,
                    )
                    .await?;
                let state = if value { "on" } else { "off" };
                println!("Favorite {} ✓", state);
            }
        }
        Command::Rename {
            account,
            folder,
            name,
            secret,
        } => {
            let mut resolved =
                resolve_verify(factory, account, folder, secret).await?;
            if resolved.verified {
                resolved.meta.set_label(name);

                let mut owner = resolved.user.write().await;
                owner
                    .update_secret(
                        &resolved.secret_id,
                        resolved.meta,
                        None,
                        None,
                    )
                    .await?;
                println!("Secret renamed ✓");
            }
        }
        Command::Del {
            account,
            folder,
            secret,
        } => {
            let resolved =
                resolve_verify(factory, account, folder, secret).await?;
            if resolved.verified {
                let prompt =
                    format!(r#"Delete "{}" (y/n)? "#, resolved.meta.label());
                if read_flag(Some(&prompt))? {
                    let mut owner = resolved.user.write().await;
                    owner.delete_secret(&resolved.secret_id).await?;
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
