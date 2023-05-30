use clap::Subcommand;

use crate::{Error, Result, TARGET};
use sos_sdk::{
    events::{AuditData, AuditEvent, AuditLogFile},
    signer::ecdsa::Address,
    vfs::File,
};
use std::{path::PathBuf, thread, time};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print the events in an audit log file
    Logs {
        /// Print each event as a line of JSON
        #[clap(short, long)]
        json: bool,

        /// Iterate from the end of the file
        #[clap(short, long)]
        reverse: bool,

        /// Limit events to displayed to this count
        #[clap(short, long)]
        count: Option<usize>,

        /// Filter to events that match the given address.
        #[clap(short, long)]
        address: Vec<Address>,

        /// Audit log file
        audit_log: PathBuf,
    },
    /// Monitor changes to an audit log file
    Monitor {
        /// Print each event as a line of JSON
        #[clap(short, long)]
        json: bool,

        /// Filter to events that match the given address.
        #[clap(short, long)]
        address: Vec<Address>,

        /// Audit log file
        audit_log: PathBuf,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Logs {
            audit_log,
            json,
            address,
            reverse,
            count,
        } => {
            logs(audit_log, json, address, reverse, count).await?;
        }
        Command::Monitor {
            audit_log,
            json,
            address,
        } => {
            monitor(audit_log, json, address).await?;
        }
    }
    Ok(())
}

/// Monitor changes in an audit log file.
pub async fn monitor(
    audit_log: PathBuf,
    json: bool,
    address: Vec<Address>,
) -> Result<()> {
    if !audit_log.is_file() {
        return Err(Error::NotFile(audit_log));
    }

    // File for iterating
    let log_file = AuditLogFile::new(&audit_log).await?;

    // File for reading event data
    let mut file = File::open(&audit_log).await?;

    let mut it = log_file.iter()?;
    let mut offset = audit_log.metadata()?.len();
    // Push iteration constraint to the end of the file
    it.set_offset(offset);

    loop {
        let step = time::Duration::from_millis(100);
        thread::sleep(step);

        let len = audit_log.metadata()?.len();
        if len > offset {
            for record in it.by_ref() {
                let record = record?;
                let event = log_file.read_event(&mut file, &record).await?;
                if !address.is_empty() && !is_address_match(&event, &address)
                {
                    continue;
                }
                print_event(event, json)?;
            }

            offset = len;

            // Adjust the iterator constraint for the consumer records
            it.set_offset(len);
        }
    }
}

/// Print events in an audit log file.
async fn logs(
    audit_log: PathBuf,
    json: bool,
    address: Vec<Address>,
    reverse: bool,
    count: Option<usize>,
) -> Result<()> {
    if !audit_log.is_file() {
        return Err(Error::NotFile(audit_log));
    }

    // File for iterating
    let log_file = AuditLogFile::new(&audit_log).await?;

    // File for reading event data
    let mut file = File::open(&audit_log).await?;

    let count = count.unwrap_or(usize::MAX);

    if reverse {
        for record in log_file.iter()?.rev().take(count) {
            let record = record?;
            let event = log_file.read_event(&mut file, &record).await?;
            if !address.is_empty() && !is_address_match(&event, &address) {
                continue;
            }
            print_event(event, json)?;
        }
    } else {
        for record in log_file.iter()?.take(count) {
            let record = record?;
            let event = log_file.read_event(&mut file, &record).await?;
            if !address.is_empty() && !is_address_match(&event, &address) {
                continue;
            }
            print_event(event, json)?;
        }
    }

    Ok(())
}

fn print_event(event: AuditEvent, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(&event)?);
    } else if let Some(data) = event.data() {
        match data {
            AuditData::Vault(vault_id) => {
                tracing::info!(
                    target: TARGET,
                    vault = ?vault_id,
                    "{} {} by {}",
                    event.time().to_rfc3339()?,
                    event.event_kind(),
                    event.address(),
                );
            }
            AuditData::Secret(vault_id, secret_id) => {
                tracing::info!(
                    target: TARGET,
                    vault = ?vault_id,
                    secret = ?secret_id,
                    "{} {} by {}",
                    event.time().to_rfc3339()?,
                    event.event_kind(),
                    event.address(),
                );
            }
        }
    } else {
        tracing::info!(
            target: TARGET,
            "{} {} by {}",
            event.time().to_rfc3339()?,
            event.event_kind(),
            event.address(),
        );
    }
    Ok(())
}

fn is_address_match(event: &AuditEvent, address: &[Address]) -> bool {
    address.iter().any(|addr| addr == event.address())
}
