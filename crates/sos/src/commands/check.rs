use clap::Subcommand;
use futures::{pin_mut, StreamExt};
use std::path::PathBuf;

use sos_net::sdk::{
    decode, hex,
    integrity::{event_integrity, vault_integrity},
    vault::{Header, Vault},
    vfs,
};

use crate::{helpers::messages::success, Error, Result};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Verify vault row checksums.
    Vault {
        /// Print the checksums for each row.
        #[clap(short, long)]
        verbose: bool,

        /// Vault file path.
        file: PathBuf,
    },
    /// Print a vault file header.
    Header {
        /// Print the header flags.
        #[clap(short, long)]
        verbose: bool,

        /// Vault file path.
        file: PathBuf,
    },
    /// Print the vault keys.
    Keys {
        /// Vault file path.
        file: PathBuf,
    },
    /// Verify event log checksums.
    Events {
        /// Print more information.
        #[clap(short, long)]
        verbose: bool,

        /// Event log file path.
        file: PathBuf,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Vault { file, verbose } => {
            verify_vault(file, verbose).await?;
        }
        Command::Header { file, verbose } => header(file, verbose).await?,
        Command::Keys { file } => keys(file).await?,
        Command::Events { verbose, file } => {
            verify_events(file, verbose).await?;
        }
    }

    Ok(())
}

/// Verify the integrity of a vault.
async fn verify_vault(file: PathBuf, verbose: bool) -> Result<()> {
    if !vfs::metadata(&file).await?.is_file() {
        return Err(Error::NotFile(file));
    }

    let stream = vault_integrity(&file);
    pin_mut!(stream);

    while let Some(event) = stream.next().await {
        let record = event?;
        if verbose {
            println!("{}", hex::encode(record?.commit()));
        }
    }

    success("Verified");
    Ok(())
}

/// Verify the integrity of an events log file.
pub(crate) async fn verify_events(
    file: PathBuf,
    verbose: bool,
) -> Result<()> {
    if !vfs::metadata(&file).await?.is_file() {
        return Err(Error::NotFile(file));
    }

    let mut commits = 0;
    let stream = event_integrity(&file);
    pin_mut!(stream);

    while let Some(event) = stream.next().await {
        let record = event?;
        if verbose {
            println!("hash: {}", hex::encode(record?.commit()));
        }
        commits += 1;
    }

    success(format!("Verified {} commit(s)", commits));
    Ok(())
}

/// Print a vault header.
pub async fn header(vault: PathBuf, verbose: bool) -> Result<()> {
    if !vfs::metadata(&vault).await?.is_file() {
        return Err(Error::NotFile(vault));
    }

    let header = Header::read_header_file(&vault).await?;
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
pub async fn keys(vault: PathBuf) -> Result<()> {
    if !vfs::metadata(&vault).await?.is_file() {
        return Err(Error::NotFile(vault));
    }

    let buffer = vfs::read(&vault).await?;
    let vault: Vault = decode(&buffer).await?;
    for id in vault.keys() {
        println!("{}", id);
    }

    Ok(())
}
