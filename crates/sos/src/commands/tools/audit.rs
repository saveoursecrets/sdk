use crate::{helpers::messages::info, Error, Result};
use clap::Subcommand;
use sos_core::AccountId;
use sos_net::sdk::{
    audit::{AuditData, AuditEvent, AuditLogFile},
    formats::FormatStreamIterator,
    vfs::{self, File},
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

        /// Limit events displayed to this amount
        #[clap(short, long)]
        count: Option<usize>,

        /// Filter to events that match the given account identifier.
        #[clap(short, long)]
        account_id: Vec<AccountId>,

        /// Audit log file
        audit_log: PathBuf,
    },
    /// Monitor changes to an audit log file
    Monitor {
        /// Print each event as a line of JSON
        #[clap(short, long)]
        json: bool,

        /// Filter to events that match the given account identifiers.
        #[clap(short, long)]
        account_id: Vec<AccountId>,

        /// Audit log file
        audit_log: PathBuf,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Logs {
            audit_log,
            json,
            account_id,
            reverse,
            count,
        } => {
            logs(audit_log, json, account_id, reverse, count).await?;
        }
        Command::Monitor {
            audit_log,
            json,
            account_id,
        } => {
            monitor(audit_log, json, account_id).await?;
        }
    }
    Ok(())
}

/// Monitor changes in an audit log file.
pub async fn monitor(
    audit_log: PathBuf,
    json: bool,
    account_id: Vec<AccountId>,
) -> Result<()> {
    if !vfs::metadata(&audit_log).await?.is_file() {
        return Err(Error::NotFile(audit_log));
    }

    // File for iterating
    let log_file = AuditLogFile::new(&audit_log).await?;

    // File for reading event data
    let mut file = File::open(&audit_log).await?;

    let mut it = log_file.iter(false).await?;
    let mut offset = audit_log.metadata()?.len();
    // Push iteration constraint to the end of the file
    it.set_offset(offset);

    loop {
        let step = time::Duration::from_millis(100);
        thread::sleep(step);

        let len = audit_log.metadata()?.len();
        if len > offset {
            while let Some(record) = it.next().await? {
                let event = log_file.read_event(&mut file, &record).await?;
                if !account_id.is_empty()
                    && !is_account_id_match(&event, &account_id)
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
    account_id: Vec<AccountId>,
    reverse: bool,
    count: Option<usize>,
) -> Result<()> {
    if !vfs::metadata(&audit_log).await?.is_file() {
        return Err(Error::NotFile(audit_log));
    }

    // File for iterating
    let log_file = AuditLogFile::new(&audit_log).await?;

    // File for reading event data
    let mut file = File::open(&audit_log).await?;

    let count = count.unwrap_or(usize::MAX);
    let mut c = 0;

    let mut it = log_file.iter(reverse).await?;
    while let Some(record) = it.next().await? {
        let event = log_file.read_event(&mut file, &record).await?;
        if !account_id.is_empty() && !is_account_id_match(&event, &account_id)
        {
            continue;
        }
        c += 1;
        print_event(event, json)?;

        if c >= count {
            break;
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
                info(format!(
                    "{} {} by {}, vault = {}",
                    event.time().to_rfc3339()?,
                    event.event_kind(),
                    event.account_id(),
                    vault_id,
                ));
            }
            AuditData::Secret(vault_id, secret_id) => {
                info(format!(
                    "{} {} by {}, vault = {}, secret = {}",
                    event.time().to_rfc3339()?,
                    event.event_kind(),
                    event.account_id(),
                    vault_id,
                    secret_id,
                ));
            }
            AuditData::MoveSecret {
                from_vault_id,
                from_secret_id,
                to_vault_id,
                to_secret_id,
            } => {
                info(format!(
                    "{} {} by {}, from = {}/{}, to = {}/{}",
                    event.time().to_rfc3339()?,
                    event.event_kind(),
                    event.account_id(),
                    from_vault_id,
                    from_secret_id,
                    to_vault_id,
                    to_secret_id,
                ));
            }
        }
    } else {
        info(format!(
            "{} {} by {}",
            event.time().to_rfc3339()?,
            event.event_kind(),
            event.account_id(),
        ));
    }
    Ok(())
}

fn is_account_id_match(event: &AuditEvent, ids: &[AccountId]) -> bool {
    ids.into_iter().any(|addr| addr == event.account_id())
}
