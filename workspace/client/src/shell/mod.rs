use std::{
    borrow::Cow,
    collections::HashMap,
    ffi::OsString,
    path::PathBuf,
    sync::{Arc, RwLock, RwLockWriteGuard},
};

use clap::{CommandFactory, Parser, Subcommand};
use sha3::{Digest, Sha3_256};

use terminal_banner::{Banner, Padding};
use url::Url;
use web3_address::ethereum::Address;

use human_bytes::human_bytes;
use sos_core::{
    generate_passphrase,
    search::Document,
    secret::{Secret, SecretId, SecretMeta, SecretRef},
    vault::{Vault, VaultAccess, VaultCommit, VaultEntry},
};
use sos_node::{
    client::{
        provider::{BoxedProvider, ProviderFactory},
        run_blocking,
    },
    sync::SyncKind,
};
use sos_readline::{
    choose, read_flag, read_line, read_line_allow_empty, read_multiline,
    read_option, read_password, Choice,
};

use secrecy::{ExposeSecret, SecretString};

use crate::{display_passphrase, switch, Error, Result};

mod editor;
mod print;

pub type ShellProvider = Arc<RwLock<BoxedProvider>>;

/// Encapsulates the state for the shell REPL.
pub struct ShellState(pub ShellProvider, pub Address, pub ProviderFactory);

/// Type for the root shell data.
pub type ShellData = Arc<RwLock<ShellState>>;

enum ConflictChoice {
    Push,
    Pull,
    Noop,
}

/// Secret storage shell.
#[derive(Parser, Debug)]
#[clap(name = "sos-shell", author, version, about, long_about = None)]
struct Shell {
    #[clap(subcommand)]
    cmd: ShellCommand,
}

#[derive(Subcommand, Debug)]
enum ShellCommand {
    /// Renew session authentication.
    #[clap(alias = "auth")]
    Authenticate,
    /// List vaults.
    Vaults,
    /// Create a new vault.
    Create {
        /// Name for the new vault.
        name: String,
    },
    /// Delete a vault.
    Remove {
        /// Vault reference, it's name or identifier.
        vault: SecretRef,
    },
    /// Select a vault.
    Use {
        /// Vault reference, it's name or identifier.
        vault: SecretRef,
    },
    /// Print information about the selected vault.
    Info,
    /// Get or set the name of the selected vault.
    Name {
        /// A new name for the vault.
        name: Option<String>,
    },
    /// Print commit status.
    Status {
        /// Print more information; include commit tree root hashes.
        #[clap(short, long)]
        verbose: bool,
    },
    /// Print commit tree leaves for the current vault.
    Tree,
    /// Print secret keys for the selected vault.
    Keys,
    /// List secrets for the selected vault.
    #[clap(alias = "ls")]
    List {
        /// Print more information
        #[clap(short, long)]
        long: bool,
    },
    /// Add a secret.
    Add {
        #[clap(subcommand)]
        cmd: Add,
    },
    /// Print a secret.
    Get {
        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Update a secret.
    Set {
        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Delete a secret.
    Del {
        /// Secret name or identifier.
        secret: SecretRef,
    },
    /// Rename a secret.
    Mv {
        /// Secret name or identifier.
        secret: SecretRef,
        /// New label for the secret.
        label: Option<String>,
    },
    /// Manage snapshots for the selected vault.
    Snapshot {
        #[clap(subcommand)]
        cmd: SnapShot,
    },
    /// Inspect the history for the selected vault.
    History {
        #[clap(subcommand)]
        cmd: History,
    },
    /// Download changes from the remote server.
    Pull {
        /// Force a pull from the remote server.
        #[clap(short, long)]
        force: bool,
    },
    /// Upload changes to the remote server.
    Push {
        /// Force a push to the remote server.
        #[clap(short, long)]
        force: bool,
    },
    /// Change encrpytion password for the selected vault.
    #[clap(alias = "passwd")]
    Password,
    /// Switch identity.
    #[clap(alias = "su")]
    Switch {
        /// Account name.
        account_name: String,
    },
    /// Print the current identity.
    Whoami,
    /// Close the selected vault.
    Close,
    /// Exit the shell.
    #[clap(alias = "q")]
    Quit,
}

#[derive(Subcommand, Debug)]
enum Add {
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
    /*
    /// Add a personal identification number.
    Pin { label: Option<String> },
    */
}

#[derive(Subcommand, Debug)]
enum SnapShot {
    /// Take a snapshot of the current WAL state.
    Take,
    /// List snapshots.
    #[clap(alias = "ls")]
    List {
        /// Print more information; includes file path and size.
        #[clap(short, long)]
        long: bool,
    },
    // TODO: support removing all existing snapshots: `purge`?
}

#[derive(Subcommand, Debug)]
enum History {
    /// Compact the currently selected vault.
    Compact {
        /// Take a snapshot before compaction.
        #[clap(short, long)]
        snapshot: bool,
    },
    /// Verify the integrity of the vault history.
    Check,
    /// List history events.
    #[clap(alias = "ls")]
    List {
        /// Print more information.
        #[clap(short, long)]
        long: bool,
    },
}

/// Attempt to read secret meta data for a reference.
fn find_secret_meta(
    cache: ShellProvider,
    secret: &SecretRef,
) -> Result<Option<(SecretId, SecretMeta)>> {
    let reader = cache.read().unwrap();
    let keeper = reader.current().ok_or(Error::NoVaultSelected)?;
    let index = keeper.index();
    let index_reader = index.read();
    if let Some(Document {
        secret_id, meta, ..
    }) = index_reader.find_by_uuid_or_label(keeper.vault().id(), secret)
    {
        Ok(Some((*secret_id, meta.clone())))
    } else {
        Ok(None)
    }
}

fn get_label(label: Option<String>) -> Result<String> {
    if let Some(label) = label {
        Ok(label)
    } else {
        Ok(read_line(Some("Label: "))?)
    }
}

fn multiline_banner(kind: &str, label: &str) {
    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::Owned(format!("[{}] {}", kind, label)))
        .text(Cow::Borrowed(
            r#"To abort enter Ctrl+C
To save enter Ctrl+D on a newline"#,
        ))
        .render();
    println!("{}", banner);
}

fn add_note(label: Option<String>) -> Result<Option<(SecretMeta, Secret)>> {
    let label = get_label(label)?;
    multiline_banner("NOTE", &label);

    if let Some(note) = read_multiline(None)? {
        let note =
            secrecy::Secret::new(note.trim_end_matches('\n').to_string());
        let secret = Secret::Note {
            text: note,
            user_data: Default::default(),
        };
        let secret_meta = SecretMeta::new(label, secret.kind());
        Ok(Some((secret_meta, secret)))
    } else {
        Ok(None)
    }
}

fn add_page(label: Option<String>) -> Result<Option<(SecretMeta, Secret)>> {
    let label = get_label(label)?;
    let title = read_line(Some("Page title: "))?;
    let mime = "text/markdown".to_string();

    multiline_banner("PAGE", &label);

    if let Some(document) = read_multiline(None)? {
        let document =
            secrecy::Secret::new(document.trim_end_matches('\n').to_string());
        let secret = Secret::Page {
            title,
            mime,
            document,
            user_data: Default::default(),
        };
        let secret_meta = SecretMeta::new(label, secret.kind());
        Ok(Some((secret_meta, secret)))
    } else {
        Ok(None)
    }
}

/*
fn add_pin(label: Option<String>) -> Result<Option<(SecretMeta, Secret)>> {
    let label = get_label(label)?;

    let number = read_password(Some("PIN: "))?;

    Secret::ensure_ascii_digits(number.expose_secret())?;

    let secret = Secret::Pin {
        number,
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label, secret.kind());
    Ok(Some((secret_meta, secret)))
}
*/

fn add_credentials(
    label: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let label = get_label(label)?;

    let mut credentials: HashMap<String, SecretString> = HashMap::new();
    loop {
        let mut name = read_line(Some("Name: "))?;
        while credentials.get(&name).is_some() {
            tracing::error!("name '{}' already exists", &name);
            name = read_line(Some("Name: "))?;
        }
        let value = read_password(Some("Value: "))?;
        credentials.insert(name, value);
        let prompt = Some("Add more credentials (y/n)? ");
        if !read_flag(prompt)? {
            break;
        }
    }

    if !credentials.is_empty() {
        let secret = Secret::List {
            items: credentials,
            user_data: Default::default(),
        };
        let secret_meta = SecretMeta::new(label, secret.kind());
        Ok(Some((secret_meta, secret)))
    } else {
        Ok(None)
    }
}

fn add_account(
    label: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let label = get_label(label)?;

    let account = read_line(Some("Account name: "))?;
    let url = read_option(Some("Website URL: "))?;
    let password = read_password(Some("Password: "))?;

    let url: Option<Url> = if let Some(url) = url {
        Some(url.parse()?)
    } else {
        None
    };

    let secret = Secret::Account {
        account,
        url,
        password,
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(label, secret.kind());
    Ok(Some((secret_meta, secret)))
}

fn add_file(
    path: String,
    label: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let file = PathBuf::from(&path);

    let name = if let Some(name) = file.file_name() {
        name.to_string_lossy().into_owned()
    } else {
        return Err(Error::FileName(file));
    };

    let mut label = if let Some(label) = label {
        label
    } else {
        read_line_allow_empty(Some("Label: "))?
    };

    if label.is_empty() {
        label = name;
    }

    let secret = read_file_secret(&path)?;
    let secret_meta = SecretMeta::new(label, secret.kind());
    Ok(Some((secret_meta, secret)))
}

fn read_file_secret(path: &str) -> Result<Secret> {
    let file = PathBuf::from(path);

    if !file.is_file() {
        return Err(Error::NotFile(file));
    }

    let name = if let Some(name) = file.file_name() {
        name.to_string_lossy().into_owned()
    } else {
        return Err(Error::FileName(file));
    };

    let mime = mime_guess::from_path(&name)
        .first()
        .map(|m| m.to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let buffer = std::fs::read(file)?;
    let size = buffer.len() as u64;
    let checksum = Sha3_256::digest(&buffer);
    let buffer = secrecy::Secret::new(buffer);
    Ok(Secret::File {
        name,
        mime,
        buffer,
        checksum: checksum.as_slice().try_into()?,
        external: false,
        size,
        user_data: Default::default(),
    })
}

fn maybe_conflict<F>(cache: ShellProvider, func: F) -> Result<()>
where
    F: FnOnce(
        &mut RwLockWriteGuard<'_, BoxedProvider>,
    ) -> sos_node::client::Result<()>,
{
    let mut writer = cache.write().unwrap();
    match func(&mut writer) {
        Ok(_) => Ok(()),
        Err(e) => match e {
            sos_node::client::Error::Conflict {
                summary,
                local,
                remote,
            } => {
                let local_hex = local.0.to_string();
                let remote_hex = remote.0.to_string();
                let local_num = local.1;
                let remote_num = remote.1;

                let banner = Banner::new()
                    .padding(Padding::one())
                    .text(Cow::Borrowed("!!! CONFLICT !!!"))
                    .text(Cow::Owned(
                        format!("A conflict was detected on {}, proceed with caution; to resolve this conflict sync with the server.", summary.name()),
                    ))
                    .text(Cow::Owned(format!("local  = {}\nremote = {}", local_hex, remote_hex)))
                    .text(Cow::Owned(format!("local = #{}, remote = #{}", local_num, remote_num)))
                    .render();
                println!("{}", banner);

                let options = [
                    Choice(
                        "Pull remote changes from the server",
                        ConflictChoice::Pull,
                    ),
                    Choice(
                        "Push local changes to the server",
                        ConflictChoice::Push,
                    ),
                    Choice("None of the above", ConflictChoice::Noop),
                ];

                let prompt =
                    Some("Choose an action to resolve the conflict: ");
                match choose(prompt, &options)? {
                    Some(choice) => match choice {
                        ConflictChoice::Pull => {
                            run_blocking(writer.pull(&summary, true))?;
                            Ok(())
                        }
                        ConflictChoice::Push => {
                            run_blocking(writer.push(&summary, true))?;
                            Ok(())
                        }
                        ConflictChoice::Noop => Ok(()),
                    },
                    None => Ok(()),
                }
            }
            _ => Err(Error::from(e)),
        },
    }
}

/// Execute the program command.
fn exec_program(program: Shell, state: ShellData) -> Result<()> {
    let reader = state.read().unwrap();
    let cache = Arc::clone(&reader.0);
    drop(reader);

    match program.cmd {
        ShellCommand::Authenticate => {
            let mut writer = cache.write().unwrap();
            run_blocking(writer.authenticate())?;
            println!("session renewed ✓");
            Ok(())
        }
        ShellCommand::Vaults => {
            let mut writer = cache.write().unwrap();
            let summaries = run_blocking(writer.load_vaults())?;
            print::summaries_list(summaries);
            Ok(())
        }
        ShellCommand::Create { name } => {
            let mut writer = cache.write().unwrap();
            let (passphrase, _summary) =
                run_blocking(writer.create_vault(name, None))?;
            display_passphrase(
                "ENCRYPTION PASSPHRASE",
                passphrase.expose_secret(),
            );
            Ok(())
        }
        ShellCommand::Remove { vault } => {
            let reader = cache.read().unwrap();
            let summary = reader
                .state()
                .find_vault(&vault)
                .ok_or(Error::VaultNotAvailable(vault.clone()))?
                .clone();
            let prompt = format!(
                r#"Permanently delete vault "{}" (y/n)? "#,
                summary.name(),
            );

            drop(reader);

            if read_flag(Some(&prompt))? {
                let mut writer = cache.write().unwrap();
                run_blocking(writer.remove_vault(&summary))?;
            }

            Ok(())
        }
        ShellCommand::Use { vault } => {
            let reader = cache.read().unwrap();
            let summary = reader
                .state()
                .find_vault(&vault)
                .cloned()
                .ok_or(Error::VaultNotAvailable(vault))?;
            drop(reader);

            let mut writer = cache.write().unwrap();
            let passphrase = read_password(Some("Passphrase: "))?;
            writer.open_vault(&summary, passphrase.expose_secret(), None)?;
            Ok(())
            //maybe_conflict(cache, |writer| {
            //run_blocking(
            //writer.open_vault(&summary, passphrase.expose_secret()),
            //)
            //})
        }
        ShellCommand::Info => {
            let reader = cache.read().unwrap();
            let keeper = reader.current().ok_or(Error::NoVaultSelected)?;
            let summary = keeper.summary();
            println!("{}", summary);
            Ok(())
        }
        ShellCommand::Keys => {
            let reader = cache.read().unwrap();
            let keeper = reader.current().ok_or(Error::NoVaultSelected)?;
            for uuid in keeper.vault().keys() {
                println!("{}", uuid);
            }
            Ok(())
        }
        ShellCommand::List { long } => {
            let reader = cache.read().unwrap();
            if let Some(keeper) = reader.current() {
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
                    if long {
                        println!("{} {}", label, secret_id);
                    } else {
                        println!("{}", label);
                    }
                }
                Ok(())
            } else {
                Err(Error::NoVaultSelected)
            }
        }
        ShellCommand::Name { name } => {
            let mut writer = cache.write().unwrap();
            let keeper =
                writer.current_mut().ok_or(Error::NoVaultSelected)?;
            let (renamed, summary, name) = if let Some(name) = name {
                keeper.set_vault_name(name.clone())?;
                (true, keeper.summary().clone(), name)
            } else {
                let name = keeper.name();
                println!("{}", name);
                (false, keeper.summary().clone(), name.to_string())
            };

            drop(writer);
            if renamed {
                maybe_conflict(cache, |writer| {
                    run_blocking(writer.set_vault_name(&summary, &name))
                })
            } else {
                Ok(())
            }
        }
        ShellCommand::Status { verbose } => {
            let reader = cache.read().unwrap();
            let keeper = reader.current().ok_or(Error::NoVaultSelected)?;
            let summary = keeper.summary().clone();
            drop(reader);

            let mut writer = cache.write().unwrap();
            let (status, pending_events) =
                run_blocking(writer.status(&summary))?;
            if verbose {
                let pair = status.pair();
                println!("local  = {}", pair.local.root_hex());
                println!("remote = {}", pair.remote.root_hex());
            }
            if let Some(pending_events) = pending_events {
                println!("{} event(s) have not been saved", pending_events);
            }
            println!("{}", status);
            Ok(())
        }
        ShellCommand::Tree => {
            let reader = cache.read().unwrap();
            let keeper = reader.current().ok_or(Error::NoVaultSelected)?;
            let summary = keeper.summary();
            if let Some(tree) = reader.commit_tree(summary) {
                if let Some(leaves) = tree.leaves() {
                    for leaf in &leaves {
                        println!("{}", hex::encode(leaf));
                    }
                    println!("leaves = {}", leaves.len());
                }
                if let Some(root) = tree.root() {
                    println!("root = {}", hex::encode(root));
                }
            }
            Ok(())
        }
        ShellCommand::Add { cmd } => {
            let mut writer = cache.write().unwrap();
            let _keeper =
                writer.current_mut().ok_or(Error::NoVaultSelected)?;
            let result = match cmd {
                Add::Note { label } => add_note(label)?,
                Add::List { label } => add_credentials(label)?,
                Add::Account { label } => add_account(label)?,
                Add::File { path, label } => add_file(path, label)?,
                Add::Page { label } => add_page(label)?,
                //Add::Pin { label } => add_pin(label)?,
            };

            drop(writer);

            if let Some((meta, secret)) = result {
                maybe_conflict(cache, |writer| {
                    run_blocking(async {
                        writer.create_secret(meta, secret).await?;
                        Ok(())
                    })
                })
            } else {
                Ok(())
            }
        }
        ShellCommand::Get { secret } => {
            let (uuid, _) = find_secret_meta(Arc::clone(&cache), &secret)?
                .ok_or(Error::SecretNotAvailable(secret.clone()))?;
            let mut writer = cache.write().unwrap();
            let (meta, secret, _) = run_blocking(writer.read_secret(&uuid))?;
            print::secret(&meta, &secret)?;
            Ok(())
        }

        ShellCommand::Set { secret } => {
            let (uuid, _) = find_secret_meta(Arc::clone(&cache), &secret)?
                .ok_or(Error::SecretNotAvailable(secret.clone()))?;

            // Read in secret data for editing.
            let reader = cache.read().unwrap();
            let keeper = reader.current().ok_or(Error::NoVaultSelected)?;
            let result =
                if let Some((secret_meta, secret, _)) = keeper.read(&uuid)? {
                    Some((uuid, secret_meta, secret))
                } else {
                    None
                };

            drop(reader);

            let (uuid, secret_meta, secret_data) =
                result.ok_or(Error::SecretNotAvailable(secret.clone()))?;

            let result = if let Secret::File {
                name, mime, buffer, ..
            } = &secret_data
            {
                if mime.starts_with("text/") {
                    editor::edit(&secret_data)?
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
                editor::edit(&secret_data)?
            };

            if let Cow::Owned(edited_secret) = result {
                maybe_conflict(cache, |writer| {
                    run_blocking(async {
                        writer
                            .update_secret(&uuid, secret_meta, edited_secret)
                            .await?;
                        Ok(())
                    })
                })
            // If the edited result was borrowed
            // it indicates that no changes were made
            } else {
                Ok(())
            }
        }
        ShellCommand::Del { secret } => {
            let (uuid, secret_meta) =
                find_secret_meta(Arc::clone(&cache), &secret)?
                    .ok_or(Error::SecretNotAvailable(secret.clone()))?;

            let prompt =
                format!(r#"Delete "{}" (y/n)? "#, secret_meta.label());
            if read_flag(Some(&prompt))? {
                let mut writer = cache.write().unwrap();
                let _keeper =
                    writer.current_mut().ok_or(Error::NoVaultSelected)?;

                drop(writer);

                maybe_conflict(cache, |writer| {
                    run_blocking(async {
                        writer.delete_secret(&uuid).await?;
                        Ok(())
                    })
                })
            } else {
                Ok(())
            }
        }
        ShellCommand::Mv { secret, label } => {
            let (uuid, _) = find_secret_meta(Arc::clone(&cache), &secret)?
                .ok_or(Error::SecretNotAvailable(secret.clone()))?;

            let reader = cache.read().unwrap();
            let keeper = reader.current().ok_or(Error::NoVaultSelected)?;
            let result =
                if let (Some(value), _) = keeper.vault().read(&uuid)? {
                    let VaultCommit(_, VaultEntry(meta_aead, secret_aead)) =
                        value.as_ref().clone();
                    Some((uuid, meta_aead, secret_aead))
                } else {
                    None
                };

            drop(reader);

            let (uuid, meta_aead, secret_aead) =
                result.ok_or(Error::SecretNotAvailable(secret.clone()))?;

            let mut writer = cache.write().unwrap();
            let keeper =
                writer.current_mut().ok_or(Error::NoVaultSelected)?;
            let label = get_label(label)?;
            let summary = keeper.summary().clone();

            let mut secret_meta = keeper.decrypt_meta(&meta_aead)?;
            secret_meta.set_label(label);
            secret_meta.touch();
            let meta_aead = keeper.encrypt_meta(&secret_meta)?;

            let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead)?;

            let event = keeper
                .vault_mut()
                .update(&uuid, commit, VaultEntry(meta_aead, secret_aead))?
                .ok_or(Error::SecretNotAvailable(secret.clone()))?;

            let event = event.into_owned();

            drop(writer);
            maybe_conflict(cache, |writer| {
                run_blocking(writer.patch(&summary, vec![event]))
            })
        }
        ShellCommand::Snapshot { cmd } => match cmd {
            SnapShot::Take => {
                let reader = cache.read().unwrap();
                let keeper =
                    reader.current().ok_or(Error::NoVaultSelected)?;
                let (snapshot, _) = reader.take_snapshot(keeper.summary())?;
                println!("Path: {}", snapshot.0.display());
                println!("Time: {}", snapshot.1);
                println!("Hash: {}", snapshot.2);
                println!("Size: {}", human_bytes(snapshot.3 as f64));
                Ok(())
            }
            SnapShot::List { long } => {
                let reader = cache.read().unwrap();
                let keeper =
                    reader.current().ok_or(Error::NoVaultSelected)?;
                let snapshots = reader
                    .snapshots()
                    .ok_or(sos_node::client::Error::SnapshotsNotEnabled)?;
                let snapshots = snapshots.list(keeper.id())?;
                if !snapshots.is_empty() {
                    for snapshot in snapshots.into_iter() {
                        if long {
                            print!(
                                "{} {} ",
                                snapshot.0.display(),
                                human_bytes(snapshot.3 as f64)
                            );
                        }
                        println!("{} {}", snapshot.1, snapshot.2);
                    }
                } else {
                    println!("No snapshots yet!");
                }
                Ok(())
            }
        },
        ShellCommand::History { cmd } => {
            match cmd {
                History::Compact { snapshot } => {
                    let reader = cache.read().unwrap();
                    let keeper =
                        reader.current().ok_or(Error::NoVaultSelected)?;
                    let summary = keeper.summary().clone();
                    if snapshot {
                        reader.take_snapshot(&summary)?;
                    }
                    drop(reader);

                    let prompt = Some("Compaction will remove history, are you sure (y/n)? ");
                    if read_flag(prompt)? {
                        let mut writer = cache.write().unwrap();
                        let (old_size, new_size) =
                            run_blocking(writer.compact(&summary))?;
                        println!("Old: {}", human_bytes(old_size as f64));
                        println!("New: {}", human_bytes(new_size as f64));
                    }
                    Ok(())
                }
                History::Check => {
                    let reader = cache.read().unwrap();
                    let keeper =
                        reader.current().ok_or(Error::NoVaultSelected)?;
                    reader.verify(keeper.summary())?;
                    println!("Verified ✓");
                    Ok(())
                }
                History::List { long } => {
                    let reader = cache.read().unwrap();
                    let keeper =
                        reader.current().ok_or(Error::NoVaultSelected)?;

                    let records = reader.history(keeper.summary())?;
                    for (commit, time, event) in records {
                        print!("{} {} ", event.event_kind(), time);
                        if long {
                            println!("{}", commit);
                        } else {
                            print!("\n");
                        }
                    }
                    Ok(())
                }
            }
        }
        ShellCommand::Pull { force } => {
            let mut writer = cache.write().unwrap();
            let keeper = writer.current().ok_or(Error::NoVaultSelected)?;
            let summary = keeper.summary().clone();
            let result = run_blocking(writer.pull(&summary, force))?;
            match result.status {
                SyncKind::Equal => println!("Up to date"),
                SyncKind::Safe => {
                    if let Some(proof) = result.after {
                        println!("Pull complete {}", proof.root_hex());
                    }
                }
                SyncKind::Force => {
                    if let Some(proof) = result.after {
                        println!("Force pull complete {}", proof.root_hex());
                    }
                }
                SyncKind::Unsafe => {
                    println!("Cannot pull safely, use the --force option if you are sure.");
                }
            }
            Ok(())
        }
        ShellCommand::Push { force } => {
            let mut writer = cache.write().unwrap();
            let keeper = writer.current().ok_or(Error::NoVaultSelected)?;
            let summary = keeper.summary().clone();
            let result = run_blocking(writer.push(&summary, force))?;
            match result.status {
                SyncKind::Equal => println!("Up to date"),
                SyncKind::Safe => {
                    if let Some(proof) = result.after {
                        println!("Push complete {}", proof.root_hex());
                    }
                }
                SyncKind::Force => {
                    if let Some(proof) = result.after {
                        println!("Force push complete {}", proof.root_hex());
                    }
                }
                SyncKind::Unsafe => {
                    println!("Cannot push safely, use the --force option if you are sure.");
                }
            }
            Ok(())
        }
        ShellCommand::Password => {
            let mut writer = cache.write().unwrap();
            let keeper =
                writer.current_mut().ok_or(Error::NoVaultSelected)?;

            let banner = Banner::new()
                .padding(Padding::one())
                .text(Cow::Borrowed("!!! CHANGE PASSWORD !!!"))
                .text(Cow::Borrowed(
                    "Changing your password is a dangerous operation, your data may be corrupted if the process is interrupted.",
                ))
                .text(Cow::Borrowed(
                    "Vault change history will be deleted.",
                ))
                .text(Cow::Borrowed(
                    "A new encryption passphrase will be generated and shown on success; you must remember this new passphrase to access this vault.",
                ))
                .render();
            println!("{}", banner);

            let prompt = Some("Are you sure (y/n)? ");
            if read_flag(prompt)? {
                let passphrase = read_password(Some("Current passphrase: "))?;
                let (new_passphrase, _) = generate_passphrase()?;

                // Basic quick verification
                keeper
                    .verify(passphrase.expose_secret())
                    .map_err(|_| Error::InvalidPassphrase)?;

                // We need a clone of the vault to avoid borrowing whilst
                // already mutably borrowed
                let vault: Vault = keeper.vault().clone();

                let new_passphrase = run_blocking(writer.change_password(
                    &vault,
                    passphrase,
                    new_passphrase,
                ))?;

                drop(writer);

                let banner = Banner::new()
                    .padding(Padding::one())
                    .text(Cow::Borrowed("SUCCESS"))
                    .text(Cow::Borrowed(
                        "Your passphrase was changed successfully, your new passphrase is shown below.",
                    ))
                    .text(Cow::Borrowed(
                        "Ensure you remember this passphrase to access your vault.",
                    ))
                    .render();
                println!("{}", banner);

                let banner = Banner::new()
                    .padding(Padding::one())
                    .text(Cow::Borrowed("NEW ENCRYPTION PASSPHRASE"))
                    .text(Cow::Borrowed(new_passphrase.expose_secret()))
                    .render();
                println!("{}", banner);
            }

            Ok(())
        }
        ShellCommand::Switch { account_name } => {
            let reader = state.read().unwrap();
            let factory = &reader.2;

            let (mut provider, address) = switch(factory, account_name)?;

            // Ensure the vault summaries are loaded
            // so that "use" is effective immediately
            run_blocking(provider.load_vaults())?;

            let mut writer = cache.write().unwrap();
            *writer = provider;

            let mut writer = state.write().unwrap();
            writer.1 = address;

            Ok(())
        }
        ShellCommand::Whoami => {
            let reader = state.read().unwrap();
            let address = reader.1;
            println!("{}", address);
            Ok(())
        }
        ShellCommand::Close => {
            let mut writer = cache.write().unwrap();
            writer.close_vault();
            Ok(())
        }
        ShellCommand::Quit => {
            std::process::exit(0);
        }
    }
}

/// Intermediary to pretty print clap parse errors.
fn exec_args<I, T>(it: I, cache: ShellData) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match Shell::try_parse_from(it) {
        Ok(program) => exec_program(program, cache)?,
        Err(e) => e.print().expect("unable to write error output"),
    }
    Ok(())
}

/// Execute a line of input in the context of the shell program.
pub fn exec(line: &str, cache: ShellData) -> Result<()> {
    if !line.trim().is_empty() {
        let mut sanitized = shell_words::split(line.trim_end_matches(' '))?;
        sanitized.insert(0, String::from("sos-shell"));
        let it = sanitized.into_iter();
        let mut cmd = Shell::command();
        if line == "-V" {
            let version = cmd.render_version();
            print!("{}", version);
        } else if line == "version" || line == "--version" {
            let version = cmd.render_long_version();
            print!("{}", version);
        } else if line == "-h" {
            cmd.print_help()?;
        } else if line == "help" || line == "--help" {
            cmd.print_long_help()?;
        } else {
            exec_args(it, cache)?;
        }
    }
    Ok(())
}
