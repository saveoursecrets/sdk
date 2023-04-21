use crate::{Error, Result};
use sos_core::audit::{AuditData, AuditEvent, AuditLogFile};
use std::{fs::File, path::PathBuf, thread, time};
use web3_address::ethereum::Address;

pub mod cli;
pub use cli::run;

/// Monitor changes in an audit log file.
pub fn monitor(
    audit_log: PathBuf,
    json: bool,
    address: Vec<Address>,
) -> Result<()> {
    if !audit_log.is_file() {
        return Err(Error::NotFile(audit_log));
    }

    // File for iterating
    let log_file = AuditLogFile::new(&audit_log)?;

    // File for reading event data
    let mut file = File::open(&audit_log)?;

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
                let event = log_file.read_event(&mut file, &record)?;
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
pub fn logs(
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
    let log_file = AuditLogFile::new(&audit_log)?;

    // File for reading event data
    let mut file = File::open(&audit_log)?;

    let count = count.unwrap_or(usize::MAX);

    if reverse {
        for record in log_file.iter()?.rev().take(count) {
            let record = record?;
            let event = log_file.read_event(&mut file, &record)?;
            if !address.is_empty() && !is_address_match(&event, &address) {
                continue;
            }
            print_event(event, json)?;
        }
    } else {
        for record in log_file.iter()?.take(count) {
            let record = record?;
            let event = log_file.read_event(&mut file, &record)?;
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
                    vault = ?vault_id,
                    "{} {} by {}",
                    event.time().to_rfc3339()?,
                    event.event_kind(),
                    event.address(),
                );
            }
            AuditData::Secret(vault_id, secret_id) => {
                tracing::info!(
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
