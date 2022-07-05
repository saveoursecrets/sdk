use std::path::PathBuf;

use sos_core::events::AuditData;

mod error;
mod iter;
mod log_file;

pub type Result<T> = std::result::Result<T, error::Error>;

pub use error::Error;
pub use iter::AuditLogFileIterator;
pub use log_file::AuditLogFile;

pub fn logs(audit_log: PathBuf, json: bool) -> Result<()> {
    if !audit_log.is_file() {
        return Err(Error::NotFile(audit_log));
    }

    let it = iter::AuditLogFileIterator::new(audit_log, true)?;
    for event in it {
        let log = event?;
        if json {
            println!("{}", serde_json::to_string(&log)?);
        } else if let Some(data) = log.data {
            match data {
                AuditData::Vault(vault_id) => {
                    tracing::info!(
                        "{} {} by {} (vault = {})",
                        log.time.to_rfc3339()?,
                        log.operation,
                        log.address,
                        vault_id,
                    );
                }
                AuditData::Secret(vault_id, secret_id) => {
                    tracing::info!(
                        "{} {} by {} (vault = {}, secret = {})",
                        log.time.to_rfc3339()?,
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
                log.time.to_rfc3339()?,
                log.operation,
                log.address,
            );
        }
    }
    Ok(())
}
