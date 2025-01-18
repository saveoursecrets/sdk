use crate::{helpers::messages::info, Error, Result};
use clap::Subcommand;
use futures::{pin_mut, StreamExt};
use sos_audit::{AuditData, AuditEvent};
use sos_core::AccountId;
use sos_vfs::{self as vfs};
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print the events in an audit log file.
    File {
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
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::File {
            audit_log,
            json,
            account_id,
            reverse,
            count,
        } => {
            file_logs(audit_log, json, account_id, reverse, count).await?;
        }
    }
    Ok(())
}

/// Print events in an audit log file.
async fn file_logs(
    audit_log: PathBuf,
    json: bool,
    account_id: Vec<AccountId>,
    reverse: bool,
    count: Option<usize>,
) -> Result<()> {
    if !vfs::metadata(&audit_log).await?.is_file() {
        return Err(Error::NotFile(audit_log));
    }

    let provider = sos_backend::audit::new_fs_provider(&audit_log);
    let count = count.unwrap_or(usize::MAX);
    let mut c = 0;

    let stream = provider.audit_stream(reverse).await?;
    pin_mut!(stream);
    while let Some(event) = stream.next().await {
        let event = event?;

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
