use anyhow::{bail, Result};
use std::path::PathBuf;

use sos_core::audit::{LogData, LogFileIterator};

use crate::LOG_TARGET;

pub fn print_audit_logs(audit_log: PathBuf, json: bool) -> Result<()> {
    if !audit_log.is_file() {
        bail!("audit log is not a file: {}", audit_log.display());
    }

    let mut it = LogFileIterator::new(audit_log, true)?;
    while let Some(log) = it.next() {
        if json {
            println!("{}", serde_json::to_string(&log)?);
        } else {
            if let Some(data) = log.data {
                match data {
                    LogData::Vault(vault_id) => {
                        log::info!(
                            target: LOG_TARGET,
                            "{} {} by {} (vault = {})",
                            log.time,
                            log.operation,
                            log.address,
                            vault_id,
                        );
                    }
                    LogData::Secret(vault_id, secret_id) => {
                        log::info!(
                            target: LOG_TARGET,
                            "{} {} by {} (vault = {}, secret = {})",
                            log.time,
                            log.operation,
                            log.address,
                            vault_id,
                            secret_id,
                        );
                    }
                }
            } else {
                log::info!(
                    target: LOG_TARGET,
                    "{} {} by {}",
                    log.time,
                    log.operation,
                    log.address,
                );
            }
        }
    }

    Ok(())
}
