use clap::Subcommand;

use std::{borrow::Cow, collections::HashSet, path::PathBuf, sync::Arc};

use futures::future::LocalBoxFuture;
use terminal_banner::{Banner, Padding};

use sos_net::client::{
    provider::ProviderFactory,
    user::{ArchiveFilter, DocumentView},
};
use sos_sdk::{
    account::AccountRef,
    search::Document,
    vault::{
        secret::{Secret, SecretId, SecretMeta, SecretRef, SecretRow},
        Summary, VaultRef,
    },
};

use crate::{
    helpers::{
        account::{resolve_folder, resolve_user, verify, Owner, USER},
        editor,
        readline::{read_flag, read_line},
        secret::{
            add_file, add_link, add_list, add_login, add_note, add_password,
            copy_secret_text, download_file_secret, normalize_tags,
            print_secret, read_file_secret, read_name, resolve_secret,
            ResolvedSecret,
        },
    },
    Error, Result,
};

use human_bytes::human_bytes;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Add a secret.
    Add {
        #[clap(subcommand)]
        cmd: AddCommand,
    },
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
    /// Copy to the clipboard.
    #[clap(alias = "cp")]
    Copy {
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
    /// Manage tags for a secret.
    #[clap(alias = "tag")]
    Tags {
        #[clap(subcommand)]
        cmd: TagCommand,
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
    /// Move a secret.
    #[clap(alias = "mv")]
    Move {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Target folder name or id.
        #[clap(short, long)]
        target: VaultRef,

        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Edit the comment for a secret.
    Comment {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Text for the comment.
        #[clap(short, long)]
        text: Option<String>,

        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Decrypt and download a file secret.
    #[clap(alias = "dl")]
    Download {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Overwrite an existing file.
        #[clap(long)]
        force: bool,

        /// Secret name or identifier.
        secret: SecretRef,

        /// Path for the decrypted file.
        file: PathBuf,
    },
    /// Move to the archive.
    Archive {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Restore from the archive.
    Unarchive {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Manage secret attachments.
    #[clap(alias = "att")]
    Attach {
        #[clap(subcommand)]
        cmd: AttachCommand,
    },
    /// Delete a secret.
    #[clap(alias = "rm")]
    Remove {
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
pub enum AttachCommand {
    /// Add an attachment.
    Add {
        #[clap(subcommand)]
        cmd: AttachAddCommand,
    },
    /// List attachments.
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

        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Print an attachment.
    Get {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Secret name or identifier.
        secret: SecretRef,

        /// Attachment name or identifier.
        attachment: SecretRef,
    },
    /// Decrypt and download a file attachment.
    #[clap(alias = "dl")]
    Download {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Overwrite an existing file.
        #[clap(long)]
        force: bool,

        /// Secret name or identifier.
        secret: SecretRef,

        /// Attachment name or identifier.
        attachment: SecretRef,

        /// Path for the decrypted file.
        file: PathBuf,
    },
    /// Remove an attachment.
    #[clap(alias = "rm")]
    Remove {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Secret name or identifier.
        secret: SecretRef,

        /// Attachment name or identifier.
        attachment: SecretRef,
    },
}

#[derive(Subcommand, Debug)]
pub enum AttachAddCommand {
    /// Add a file attachment.
    File {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Name of the attachment.
        #[clap(short, long)]
        name: Option<String>,

        /// File path to attach.
        #[clap(short, long)]
        path: Option<PathBuf>,

        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Add a note attachment.
    Note {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Name of the attachment.
        #[clap(short, long)]
        name: Option<String>,

        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Add a link attachment.
    Link {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Name of the attachment.
        #[clap(short, long)]
        name: Option<String>,

        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Add a password attachment.
    Password {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Name of the attachment.
        #[clap(short, long)]
        name: Option<String>,

        /// Secret name or identifier.
        secret: SecretRef,
    },
}

#[derive(Subcommand, Debug)]
pub enum TagCommand {
    /// Add tags.
    Add {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Comma separated tags.
        #[clap(short, long)]
        tags: String,

        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// List tags.
    #[clap(alias = "ls")]
    List {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Remove tags.
    #[clap(alias = "rm")]
    Remove {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Comma separated tags.
        #[clap(short, long)]
        tags: String,

        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Remove all tags.
    Clear {
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
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Comma separated tags.
        #[clap(short, long)]
        tags: Option<String>,

        /// Name of the secret.
        #[clap(short, long)]
        name: Option<String>,
    },
    /// Add a list of credentials.
    List {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Comma separated tags.
        #[clap(short, long)]
        tags: Option<String>,

        /// Name of the secret.
        #[clap(short, long)]
        name: Option<String>,
    },
    /// Add a service login password.
    Login {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Comma separated tags.
        #[clap(short, long)]
        tags: Option<String>,

        /// Name of the secret.
        #[clap(short, long)]
        name: Option<String>,
    },
    /// Add a file.
    File {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Comma separated tags.
        #[clap(short, long)]
        tags: Option<String>,

        /// Name of the secret.
        #[clap(short, long)]
        name: Option<String>,

        /// File path.
        file: String,
    },
    /*
    /// Add a page.
    Page {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Folder name or id.
        #[clap(short, long)]
        folder: Option<VaultRef>,

        /// Comma separated tags.
        #[clap(short, long)]
        tags: Option<String>,

        /// Name of the secret.
        #[clap(short, long)]
        name: Option<String>,
    },
    */
}

/// Predicate used to locate a folder.
enum FolderPredicate<'a> {
    /// User supplied reference to a folder.
    Ref(Option<&'a VaultRef>),
    /// Closure that can be used to selected a specific folder.
    ///
    /// Particularly useful for commands such as `unarchive` which
    /// must always use the special archive folder.
    Func(Box<dyn Fn(&mut Owner) -> LocalBoxFuture<Result<Summary>>>),
}

async fn resolve_verify<'a>(
    factory: ProviderFactory,
    account: Option<&AccountRef>,
    predicate: FolderPredicate<'a>,
    secret: &SecretRef,
) -> Result<ResolvedSecret> {
    let is_shell = USER.get().is_some();

    let mut user = resolve_user(account, factory, true).await?;

    let (summary, should_open) = match predicate {
        FolderPredicate::Ref(folder) => (
            resolve_folder(&user, folder)
                .await?
                .ok_or_else(|| Error::NoFolderFound)?,
            true,
        ),
        FolderPredicate::Func(closure) => {
            let summary = closure(&mut user).await?;
            (summary, false)
        }
    };

    if !is_shell || should_open {
        let mut owner = user.write().await;
        owner.open_folder(&summary).await?;
    }

    let (secret_id, meta) =
        resolve_secret(Arc::clone(&user), &summary, secret)
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
            let user = resolve_user(account.as_ref(), factory, true).await?;
            let owner = user.read().await;
            let archive_folder = owner
                .storage
                .state()
                .find(|s| s.flags().is_archive())
                .cloned();

            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            let archive_filter = archive_folder.map(|s| ArchiveFilter {
                id: *s.id(),
                include_documents: summary.flags().is_archive(),
            });

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
                    .ok_or(Error::FolderNotFound(folder.to_string()))?;
                views = vec![DocumentView::Vault(*summary.id())];
            } else if favorites {
                views = vec![DocumentView::Favorites];
            }

            let documents =
                owner.index().query_view(views, archive_filter)?;
            let docs: Vec<&Document> = documents.iter().collect();
            print_documents(&docs, verbose)?;
        }
        Command::Add { cmd } => {
            let (account, folder) = match &cmd {
                AddCommand::Note {
                    account, folder, ..
                } => (account, folder),
                AddCommand::List {
                    account, folder, ..
                } => (account, folder),
                AddCommand::Login {
                    account, folder, ..
                } => (account, folder),
                AddCommand::File {
                    account, folder, ..
                } => (account, folder),
                /*
                AddCommand::Page {
                    account, folder, ..
                } => (account, folder),
                */
            };

            let user = resolve_user(account.as_ref(), factory, true).await?;
            let summary = resolve_folder(&user, folder.as_ref())
                .await?
                .ok_or_else(|| Error::NoFolderFound)?;

            if !is_shell || folder.is_some() {
                let mut owner = user.write().await;
                owner.open_folder(&summary).await?;
            }

            let mut owner = user.write().await;
            let result = match cmd {
                AddCommand::Note { name, tags, .. } => add_note(name, tags)?,
                AddCommand::List { name, tags, .. } => add_list(name, tags)?,
                AddCommand::Login { name, tags, .. } => {
                    add_login(name, tags)?
                }
                AddCommand::File {
                    file, name, tags, ..
                } => add_file(file, name, tags)?,
                //AddCommand::Page { name, tags, .. } => add_page(name, tags)?,
            };

            if let Some((meta, secret)) = result {
                owner.create_secret(meta, secret, None).await?;
                println!("Secret created ✓");
            }
        }
        Command::Get {
            account,
            folder,
            secret,
        } => {
            let resolved = resolve_verify(
                factory,
                account.as_ref(),
                FolderPredicate::Ref(folder.as_ref()),
                &secret,
            )
            .await?;
            if resolved.verified {
                let mut owner = resolved.user.write().await;
                let (data, _) =
                    owner.read_secret(&resolved.secret_id, None).await?;
                print_secret(&data.meta, &data.secret)?;
            }
        }
        Command::Copy {
            account,
            folder,
            secret,
        } => {
            let resolved = resolve_verify(
                factory,
                account.as_ref(),
                FolderPredicate::Ref(folder.as_ref()),
                &secret,
            )
            .await?;
            if resolved.verified {
                let mut owner = resolved.user.write().await;
                let (data, _) =
                    owner.read_secret(&resolved.secret_id, None).await?;
                let copied = copy_secret_text(&data.secret)?;
                if copied {
                    println!("Copied to clipboard ✓");
                } else {
                    return Err(Error::ClipboardCopy);
                }
            }
        }
        Command::Info {
            account,
            folder,
            secret,
            debug,
            json,
        } => {
            let resolved = resolve_verify(
                factory,
                account.as_ref(),
                FolderPredicate::Ref(folder.as_ref()),
                &secret,
            )
            .await?;
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
        Command::Tags { cmd } => {
            let (account, folder, secret) = match &cmd {
                TagCommand::List {
                    account,
                    folder,
                    secret,
                } => (account, folder, secret),
                TagCommand::Add {
                    account,
                    folder,
                    secret,
                    ..
                } => (account, folder, secret),
                TagCommand::Remove {
                    account,
                    folder,
                    secret,
                    ..
                } => (account, folder, secret),
                TagCommand::Clear {
                    account,
                    folder,
                    secret,
                } => (account, folder, secret),
            };

            let mut resolved = resolve_verify(
                factory,
                account.as_ref(),
                FolderPredicate::Ref(folder.as_ref()),
                secret,
            )
            .await?;
            if resolved.verified {
                let save_updates = match cmd {
                    TagCommand::List { .. } => {
                        let mut tags: Vec<_> =
                            resolved.meta.tags().iter().collect();
                        tags.sort();
                        for tag in tags {
                            println!("{}", tag);
                        }
                        false
                    }
                    TagCommand::Add { tags, .. } => {
                        let tags = normalize_tags(Some(tags));
                        if let Some(tags) = &tags {
                            let union: HashSet<_> = resolved
                                .meta
                                .tags()
                                .union(tags)
                                .cloned()
                                .collect();
                            resolved.meta.set_tags(union);
                        }
                        true
                    }
                    TagCommand::Remove { tags, .. } => {
                        let tags = normalize_tags(Some(tags));
                        if let Some(tags) = &tags {
                            resolved
                                .meta
                                .tags_mut()
                                .retain(|t| !tags.contains(t));
                        }
                        true
                    }
                    TagCommand::Clear { .. } => {
                        resolved.meta.set_tags(HashSet::new());
                        true
                    }
                };

                if save_updates {
                    let mut owner = resolved.user.write().await;
                    owner
                        .update_secret(
                            &resolved.secret_id,
                            resolved.meta,
                            None,
                            None,
                            None,
                        )
                        .await?;
                }
            }
        }
        Command::Update {
            account,
            folder,
            secret,
        } => {
            let resolved = resolve_verify(
                factory,
                account.as_ref(),
                FolderPredicate::Ref(folder.as_ref()),
                &secret,
            )
            .await?;
            if resolved.verified {
                let mut owner = resolved.user.write().await;
                let (data, _) =
                    owner.read_secret(&resolved.secret_id, None).await?;

                let result =
                    if let Secret::File { content, .. } = &data.secret {
                        if content.mime().starts_with("text/") {
                            editor::edit(&data.secret)?
                        } else {
                            println!(
                                "Binary {} {} {}",
                                content.name(),
                                content.mime(),
                                human_bytes(content.size() as f64)
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
            let mut resolved = resolve_verify(
                factory,
                account.as_ref(),
                FolderPredicate::Ref(folder.as_ref()),
                &secret,
            )
            .await?;
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
            let mut resolved = resolve_verify(
                factory,
                account.as_ref(),
                FolderPredicate::Ref(folder.as_ref()),
                &secret,
            )
            .await?;
            if resolved.verified {
                resolved.meta.set_label(name);

                let mut owner = resolved.user.write().await;
                owner
                    .update_secret(
                        &resolved.secret_id,
                        resolved.meta,
                        None,
                        None,
                        None,
                    )
                    .await?;
                println!("Secret renamed ✓");
            }
        }
        Command::Move {
            account,
            folder,
            target,
            secret,
        } => {
            let resolved = resolve_verify(
                factory,
                account.as_ref(),
                FolderPredicate::Ref(folder.as_ref()),
                &secret,
            )
            .await?;

            let to = Some(target.clone());
            let to = resolve_folder(&resolved.user, to.as_ref()).await?;
            let to =
                to.ok_or_else(|| Error::FolderNotFound(target.to_string()))?;
            if resolved.verified {
                let mut owner = resolved.user.write().await;
                owner
                    .move_secret(&resolved.secret_id, &resolved.summary, &to)
                    .await?;
                println!("Secret moved ✓");
            }
        }
        Command::Remove {
            account,
            folder,
            secret,
        } => {
            let resolved = resolve_verify(
                factory,
                account.as_ref(),
                FolderPredicate::Ref(folder.as_ref()),
                &secret,
            )
            .await?;
            if resolved.verified {
                let prompt = format!(
                    r#"Delete secret "{}" (y/n)? "#,
                    resolved.meta.label()
                );
                if read_flag(Some(&prompt))? {
                    let mut owner = resolved.user.write().await;
                    owner.delete_secret(&resolved.secret_id, None).await?;
                    println!("Secret deleted ✓");
                }
            }
        }
        Command::Comment {
            account,
            folder,
            secret,
            text,
        } => {
            let resolved = resolve_verify(
                factory,
                account.as_ref(),
                FolderPredicate::Ref(folder.as_ref()),
                &secret,
            )
            .await?;
            if resolved.verified {
                let mut data = {
                    let mut owner = resolved.user.write().await;
                    let (data, _) =
                        owner.read_secret(&resolved.secret_id, None).await?;
                    data
                };

                let (update, value) = if let Some(text) = text {
                    (true, Some(text))
                } else {
                    let comment_text =
                        data.secret.user_data().comment().unwrap_or("");
                    match editor::edit_text(comment_text)? {
                        Cow::Owned(s) => (true, Some(s)),
                        Cow::Borrowed(_) => {
                            println!("No changes detected");
                            (false, None)
                        }
                    }
                };

                if update {
                    // Treat the empty string as None
                    let value = if let Some(value) = value {
                        if value.is_empty() {
                            None
                        } else {
                            Some(value)
                        }
                    } else {
                        None
                    };
                    data.secret.user_data_mut().set_comment(value);
                    let mut owner = resolved.user.write().await;
                    owner
                        .update_secret(
                            &resolved.secret_id,
                            resolved.meta,
                            Some(data.secret),
                            None,
                            None,
                        )
                        .await?;
                    println!("Secret updated ✓");
                }
            }
        }
        Command::Download {
            account,
            folder,
            secret,
            force,
            file,
        } => {
            let resolved = resolve_verify(
                factory,
                account.as_ref(),
                FolderPredicate::Ref(folder.as_ref()),
                &secret,
            )
            .await?;
            if resolved.verified {
                if file.exists() && !force {
                    return Err(Error::FileExists(file));
                }

                let data = {
                    let mut owner = resolved.user.write().await;
                    let (data, _) =
                        owner.read_secret(&resolved.secret_id, None).await?;
                    data
                };

                download_file_secret(&resolved, file, data.secret).await?;
            }
        }
        Command::Archive {
            account,
            folder,
            secret,
        } => {
            let resolved = resolve_verify(
                factory,
                account.as_ref(),
                FolderPredicate::Ref(folder.as_ref()),
                &secret,
            )
            .await?;
            if resolved.verified {
                let mut owner = resolved.user.write().await;
                owner
                    .archive(&resolved.summary, &resolved.secret_id)
                    .await?;
                println!("Moved to archive ✓");
            }
        }
        Command::Unarchive { account, secret } => {
            let original_folder = if is_shell {
                let user =
                    resolve_user(account.as_ref(), factory.clone(), false)
                        .await?;
                let owner = user.read().await;
                owner.storage.current().map(|g| g.summary().clone())
            } else {
                None
            };

            let resolved = resolve_verify(
                factory,
                account.as_ref(),
                FolderPredicate::Func(Box::new(|user| {
                    Box::pin(async {
                        let owner = user.write().await;
                        Ok(owner
                            .archive_folder()
                            .ok_or_else(|| Error::NoArchiveFolder)?)
                    })
                })),
                &secret,
            )
            .await?;

            if resolved.verified {
                let mut owner = resolved.user.write().await;
                owner
                    .unarchive(
                        &resolved.summary,
                        &resolved.secret_id,
                        &resolved.meta,
                    )
                    .await?;
                println!("Restored from archive ✓");
                if let Some(folder) = original_folder {
                    owner.open_folder(&folder).await?;
                }
            }
        }
        Command::Attach { cmd } => attachment(factory, cmd).await?,
    }

    Ok(())
}

async fn attachment(
    factory: ProviderFactory,
    cmd: AttachCommand,
) -> Result<()> {
    let (account, folder, secret) = match &cmd {
        AttachCommand::List {
            account,
            folder,
            secret,
            ..
        } => (account, folder, secret),
        AttachCommand::Add { cmd } => match cmd {
            AttachAddCommand::File {
                account,
                folder,
                secret,
                ..
            } => (account, folder, secret),
            AttachAddCommand::Note {
                account,
                folder,
                secret,
                ..
            } => (account, folder, secret),
            AttachAddCommand::Link {
                account,
                folder,
                secret,
                ..
            } => (account, folder, secret),
            AttachAddCommand::Password {
                account,
                folder,
                secret,
                ..
            } => (account, folder, secret),
        },
        AttachCommand::Get {
            account,
            folder,
            secret,
            ..
        } => (account, folder, secret),
        AttachCommand::Download {
            account,
            folder,
            secret,
            ..
        } => (account, folder, secret),
        AttachCommand::Remove {
            account,
            folder,
            secret,
            ..
        } => (account, folder, secret),
    };

    let resolved = resolve_verify(
        factory.clone(),
        account.as_ref(),
        FolderPredicate::Ref(folder.as_ref()),
        secret,
    )
    .await?;
    if resolved.verified {
        let mut data = {
            let mut owner = resolved.user.write().await;
            let (data, _) =
                owner.read_secret(&resolved.secret_id, None).await?;
            data
        };

        let new_secret = match cmd {
            AttachCommand::List { verbose, .. } => {
                for (index, row) in
                    data.secret.user_data().fields().iter().enumerate()
                {
                    if verbose {
                        println!(
                            "{}) {} {}",
                            index + 1,
                            row.id(),
                            row.meta().label()
                        );
                    } else {
                        println!("{}) {}", index + 1, row.meta().label());
                    }
                }
                None
            }
            AttachCommand::Add { cmd } => match cmd {
                AttachAddCommand::File { name, path, .. } => {
                    let name = read_name(name)?;
                    if data.secret.find_attachment_by_name(&name).is_some() {
                        return Err(Error::AttachmentExists(name));
                    }

                    let file = if let Some(file) = path {
                        file
                    } else {
                        PathBuf::from(read_line(Some("File: "))?)
                    };

                    let secret: Secret = file.try_into()?;
                    let meta = SecretMeta::new(name, secret.kind());
                    let attachment =
                        SecretRow::new(SecretId::new_v4(), meta, secret);
                    data.secret.attach(attachment);
                    Some(data.secret)
                }
                AttachAddCommand::Note { name, .. } => {
                    let name = read_name(name)?;
                    if data.secret.find_attachment_by_name(&name).is_some() {
                        return Err(Error::AttachmentExists(name));
                    }

                    if let Some((meta, secret)) = add_note(Some(name), None)?
                    {
                        let attachment =
                            SecretRow::new(SecretId::new_v4(), meta, secret);
                        data.secret.attach(attachment);
                        Some(data.secret)
                    } else {
                        None
                    }
                }
                AttachAddCommand::Link { name, .. } => {
                    let name = read_name(name)?;
                    if data.secret.find_attachment_by_name(&name).is_some() {
                        return Err(Error::AttachmentExists(name));
                    }

                    if let Some((meta, secret)) = add_link(Some(name), None)?
                    {
                        let attachment =
                            SecretRow::new(SecretId::new_v4(), meta, secret);
                        data.secret.attach(attachment);
                        Some(data.secret)
                    } else {
                        None
                    }
                }
                AttachAddCommand::Password { name, .. } => {
                    let name = read_name(name)?;
                    if data.secret.find_attachment_by_name(&name).is_some() {
                        return Err(Error::AttachmentExists(name));
                    }

                    if let Some((meta, secret)) =
                        add_password(Some(name), None)?
                    {
                        let attachment =
                            SecretRow::new(SecretId::new_v4(), meta, secret);
                        data.secret.attach(attachment);
                        Some(data.secret)
                    } else {
                        None
                    }
                }
            },
            AttachCommand::Get { attachment, .. } => {
                let existing = data.secret.find_attachment(&attachment);
                if let Some(existing) = existing {
                    print_secret(existing.meta(), existing.secret())?;
                    None
                } else {
                    return Err(Error::AttachmentNotFound(attachment));
                }
            }
            AttachCommand::Download {
                force,
                file,
                attachment,
                ..
            } => {
                if file.exists() && !force {
                    return Err(Error::FileExists(file));
                }

                let existing =
                    data.secret.find_attachment(&attachment).cloned();
                if let Some(existing) = existing {
                    download_file_secret(&resolved, file, existing.into())
                        .await?;
                    None
                } else {
                    return Err(Error::AttachmentNotFound(attachment));
                }
            }
            AttachCommand::Remove { attachment, .. } => {
                let existing =
                    data.secret.find_attachment(&attachment).cloned();
                if let Some(existing) = existing {
                    data.secret.detach(existing.id());
                    Some(data.secret)
                } else {
                    return Err(Error::AttachmentNotFound(attachment));
                }
            }
        };

        if let Some(new_secret) = new_secret {
            let mut owner = resolved.user.write().await;
            owner
                .update_secret(
                    &resolved.secret_id,
                    resolved.meta,
                    Some(new_secret),
                    None,
                    None,
                )
                .await?;
            println!("Secret updated ✓");
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
