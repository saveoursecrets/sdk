use std::path::PathBuf;

use sos_core::{
    address::AddressStr,
    constants::AUDIT_IDENTITY,
    serde_binary::{
        binary_rw::{BinaryReader, Endian, FileStream, OpenType, SeekStream},
        Deserializer,
    },
    AuditData, AuditLogFile,
};

mod error;

pub type Result<T> = std::result::Result<T, error::Error>;

pub use error::Error;

pub fn logs(
    audit_log: PathBuf,
    json: bool,
    address: Vec<AddressStr>,
) -> Result<()> {
    if !audit_log.is_file() {
        return Err(Error::NotFile(audit_log));
    }

    let log_file = AuditLogFile::new(&audit_log)?;

    let mut stream = FileStream::new(&audit_log, OpenType::Open)?;
    let mut reader = BinaryReader::new(&mut stream, Endian::Big);
    reader.seek(AUDIT_IDENTITY.len())?;

    let mut deserializer = Deserializer { reader };

    for _record in log_file.iter()? {
        //println!("record: {:#?}", record);
        let event = AuditLogFile::decode_row(&mut deserializer)?;

        if !address.is_empty() {
            if address
                .iter()
                .position(|addr| addr == event.address())
                .is_none()
            {
                continue;
            }
        }

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
    }

    Ok(())
}
