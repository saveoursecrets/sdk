use std::path::PathBuf;

use sos_core::events::{AuditData, LogFileIterator};

mod error;

pub type Result<T> = std::result::Result<T, error::Error>;
pub use error::Error;

pub fn logs(audit_log: PathBuf, json: bool) -> Result<()> {
    if !audit_log.is_file() {
        return Err(Error::NotFile(audit_log));
    }

    let mut it = LogFileIterator::new(audit_log, true)?;
    while let Some(log) = it.next() {
        if json {
            println!("{}", serde_json::to_string(&log)?);
        } else {
            if let Some(data) = log.data {
                match data {
                    AuditData::Vault(vault_id) => {
                        tracing::info!(
                            "{} {} by {} (vault = {})",
                            log.time,
                            log.operation,
                            log.address,
                            vault_id,
                        );
                    }
                    AuditData::Secret(vault_id, secret_id) => {
                        tracing::info!(
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
                tracing::info!(
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
