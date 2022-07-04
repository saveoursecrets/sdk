use std::{
    borrow::Cow,
    collections::HashMap,
    ffi::OsString,
    path::PathBuf,
    sync::{Arc, RwLock, RwLockWriteGuard},
};

use clap::{CommandFactory, Parser, Subcommand};

use terminal_banner::{Banner, Padding};
use url::Url;

use human_bytes::human_bytes;
use sos_core::{
    secret::{Secret, SecretId, SecretMeta, SecretRef},
    vault::{Vault, VaultAccess, VaultCommit, VaultEntry},
    CommitHash,
};
use sos_readline::{
    read_flag, read_line, read_line_allow_empty, read_multiline, read_option,
    read_password,
};

use crate::{
    display_passphrase, run_blocking, Cache, ClientCache, Error, Result,
};

mod editor;
mod print;

/// Secret storage shell.
#[derive(Parser, Debug)]
#[clap(name = "sos-shell", author, version, about, long_about = None)]
struct Shell {
    #[clap(subcommand)]
    cmd: ShellCommand,
}

#[derive(Subcommand, Debug)]
enum ShellCommand {
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
    Name { name: Option<String> },
    /// Print commit status.
    Status,
    /// Print commit tree leaves for the WAL of the current vault.
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
    Get { secret: SecretRef },
    /// Update a secret.
    Set { secret: SecretRef },
    /// Delete a secret.
    Del { secret: SecretRef },
    /// Rename a secret.
    Mv {
        secret: SecretRef,
        label: Option<String>,
    },
    /// Manage snapshots for the selected vault.
    Snapshot {
        #[clap(subcommand)]
        cmd: SnapShot,
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
}

#[derive(Subcommand, Debug)]
enum SnapShot {
    /// Take a snapshot of the current WAL state.
    Take,
    /// List snapshots.
    #[clap(alias = "ls")]
    List {
        /// Print more file path and size
        #[clap(short, long)]
        long: bool,
    },
}

/// Attempt to read secret meta data for a reference.
fn find_secret_meta(
    cache: Arc<RwLock<Cache>>,
    secret: &SecretRef,
) -> Result<Option<(SecretId, SecretMeta)>> {
    let reader = cache.read().unwrap();
    let keeper = reader.current().ok_or(Error::NoVaultSelected)?;
    let meta_data = keeper.meta_data()?;
    if let Some((uuid, secret_meta)) =
        keeper.find_by_uuid_or_label(&meta_data, secret)
    {
        Ok(Some((*uuid, secret_meta.clone())))
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

fn add_note(label: Option<String>) -> Result<Option<(SecretMeta, Secret)>> {
    let label = get_label(label)?;
    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::Owned(format!("[NOTE] {}", label)))
        .text(Cow::Borrowed(
            r#"To abort the note enter Ctrl+C
To save the note enter Ctrl+D on a newline"#,
        ))
        .render();
    println!("{}", banner);

    if let Some(note) = read_multiline(None)? {
        let note = note.trim_end_matches('\n').to_string();
        let secret = Secret::Note(note);
        let secret_meta = SecretMeta::new(label, secret.kind());
        Ok(Some((secret_meta, secret)))
    } else {
        Ok(None)
    }
}

fn add_credentials(
    label: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let label = get_label(label)?;

    let mut credentials: HashMap<String, String> = HashMap::new();
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
        let secret = Secret::List(credentials);
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
    Ok(Secret::File { name, mime, buffer })
}

fn maybe_conflict<F>(cache: Arc<RwLock<Cache>>, func: F) -> Result<()>
where
    F: FnOnce(&mut RwLockWriteGuard<'_, Cache>) -> Result<()>,
{
    let mut writer = cache.write().unwrap();
    match func(&mut writer) {
        Ok(_) => Ok(()),
        Err(e) => match e {
            Error::Conflict(info) => {
                let local_hex = hex::encode(info.local.0);
                let remote_hex = hex::encode(info.remote.0);

                let local_num = info.local.1;
                let remote_num = info.remote.1;

                let should_pull = remote_num >= local_num;
                let sync_title = if should_pull { "pull" } else { "push" };

                let banner = Banner::new()
                    .padding(Padding::one())
                    .text(Cow::Borrowed("!!! CONFLICT !!!"))
                    .text(Cow::Owned(
                        format!("A conflict was detected on {}, proceed with caution; to resolve this conflict sync with the server.", info.summary.name()),
                    ))
                    .text(Cow::Owned(format!("local  = {}\nremote = {}", local_hex, remote_hex)))
                    .text(Cow::Owned(format!("local = #{}, remote = #{}", local_num, remote_num)))
                    .render();
                println!("{}", banner);

                let prompt = format!(
                    "Sync with the server using a {} (y/n)? ",
                    sync_title
                );

                if read_flag(Some(&prompt))? {
                    if should_pull {
                        run_blocking(writer.force_pull(&info.summary))
                    } else {
                        run_blocking(writer.force_push(&info.summary))
                    }
                } else {
                    Ok(())
                }
            }
            _ => Err(e),
        },
    }
}

/// Execute the program command.
fn exec_program(program: Shell, cache: Arc<RwLock<Cache>>) -> Result<()> {
    match program.cmd {
        ShellCommand::Vaults => {
            let mut writer = cache.write().unwrap();
            let summaries = run_blocking(writer.load_vaults())?;
            print::summaries_list(summaries);
            Ok(())
        }
        ShellCommand::Create { name } => {
            let mut writer = cache.write().unwrap();
            let passphrase = run_blocking(writer.create_vault(name))?;
            display_passphrase("ENCRYPTION PASSPHRASE", &passphrase);
            Ok(())
        }
        ShellCommand::Remove { vault } => {
            let reader = cache.read().unwrap();
            let summary = reader
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
                .find_vault(&vault)
                .cloned()
                .ok_or(Error::VaultNotAvailable(vault))?;
            drop(reader);

            let password = read_password(Some("Passphrase: "))?;
            maybe_conflict(cache, |writer| {
                run_blocking(writer.open_vault(&summary, &password))
            })
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
                let meta = keeper.meta_data()?;
                for (uuid, secret_meta) in meta {
                    let label = secret_meta.label();
                    let short_name = secret_meta.short_name();
                    print!("[{}] ", short_name);
                    if long {
                        println!("{} {}", label, uuid);
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
        ShellCommand::Status => {
            let reader = cache.read().unwrap();
            let keeper = reader.current().ok_or(Error::NoVaultSelected)?;
            let (client_proof, server_proof) =
                run_blocking(reader.vault_status(keeper.summary()))?;
            println!("local  = {}", CommitHash(client_proof.0));
            println!("remote = {}", CommitHash(server_proof.0));
            Ok(())
        }
        ShellCommand::Tree => {
            let reader = cache.read().unwrap();
            let keeper = reader.current().ok_or(Error::NoVaultSelected)?;
            let summary = keeper.summary();
            if let Some(tree) = reader.wal_tree(summary) {
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
            let keeper =
                writer.current_mut().ok_or(Error::NoVaultSelected)?;
            let summary = keeper.summary().clone();
            let result = match cmd {
                Add::Note { label } => add_note(label)?,
                Add::List { label } => add_credentials(label)?,
                Add::Account { label } => add_account(label)?,
                Add::File { path, label } => add_file(path, label)?,
            };

            let result = if let Some((secret_meta, secret)) = result {
                let event = keeper.create(secret_meta, secret)?;
                // Must call into_owned() on the event to prevent
                // attempting to borrow mutably twice
                Some((summary, event.into_owned()))
            } else {
                None
            };

            drop(writer);

            if let Some((summary, event)) = result {
                maybe_conflict(cache, |writer| {
                    run_blocking(writer.patch_vault(&summary, vec![event]))
                })
            } else {
                Ok(())
            }
        }
        ShellCommand::Get { secret } => {
            let (uuid, _) = find_secret_meta(Arc::clone(&cache), &secret)?
                .ok_or(Error::SecretNotAvailable(secret.clone()))?;
            let mut writer = cache.write().unwrap();
            let keeper =
                writer.current_mut().ok_or(Error::NoVaultSelected)?;
            let summary = keeper.summary().clone();

            if let Some((secret_meta, secret_data, event)) =
                keeper.read(&uuid)?
            {
                // Must call into_owned() on the event to prevent
                // attempting to borrow mutably twice
                let event = event.into_owned();

                print::secret(&secret_meta, &secret_data);
                run_blocking(writer.patch_vault(&summary, vec![event]))
            } else {
                Err(Error::SecretNotAvailable(secret))
            }
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

            let result =
                if let Secret::File { name, mime, buffer } = &secret_data {
                    if mime.starts_with("text/") {
                        editor::edit(&secret_data)?
                    } else {
                        println!(
                            "Binary {} {} {}",
                            name,
                            mime,
                            human_bytes(buffer.len() as f64)
                        );
                        let file_path = read_line(Some("File path: "))?;
                        Cow::Owned(read_file_secret(&file_path)?)
                    }
                } else {
                    editor::edit(&secret_data)?
                };

            if let Cow::Owned(edited_secret) = result {
                let mut writer = cache.write().unwrap();
                let keeper =
                    writer.current_mut().ok_or(Error::NoVaultSelected)?;

                let summary = keeper.summary().clone();

                let event = keeper
                    .update(&uuid, secret_meta, edited_secret)?
                    .ok_or(Error::SecretNotAvailable(secret))?;

                let event = event.into_owned();
                drop(writer);

                maybe_conflict(cache, |writer| {
                    run_blocking(writer.patch_vault(&summary, vec![event]))
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
                let keeper =
                    writer.current_mut().ok_or(Error::NoVaultSelected)?;
                let summary = keeper.summary().clone();
                if let Some(event) = keeper.delete(&uuid)? {
                    // Must call into_owned() on the event to prevent
                    // attempting to borrow mutably twice
                    let event = event.into_owned();

                    drop(writer);
                    maybe_conflict(cache, |writer| {
                        run_blocking(
                            writer.patch_vault(&summary, vec![event]),
                        )
                    })
                } else {
                    Err(Error::SecretNotAvailable(secret))
                }
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
            let meta_aead = keeper.encrypt_meta(&secret_meta)?;

            let (commit, _) = Vault::commit_hash(&meta_aead, &secret_aead)?;

            let event = keeper
                .vault_mut()
                .update(&uuid, commit, VaultEntry(meta_aead, secret_aead))?
                .ok_or(Error::SecretNotAvailable(secret.clone()))?;

            let event = event.into_owned();

            drop(writer);
            maybe_conflict(cache, |writer| {
                run_blocking(writer.patch_vault(&summary, vec![event]))
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
                let snapshots = reader.snapshots().list(keeper.id())?;
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
        ShellCommand::Whoami => {
            let reader = cache.read().unwrap();
            let address = reader.address()?;
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
fn exec_args<I, T>(it: I, cache: Arc<RwLock<Cache>>) -> Result<()>
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
pub fn exec(line: &str, cache: Arc<RwLock<Cache>>) -> Result<()> {
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
