use std::{path::PathBuf, io::{Read, Write}, fs::{File, OpenOptions}};

use sos_core::{
    address::AddressStr,
    constants::AUDIT_IDENTITY,
    iter::FileItem,
    serde_binary::{
        binary_rw::{BinaryReader, Endian, FileStream, OpenType, SeekStream},
        Deserializer,
    },
    AuditData, AuditLogFile, AuditEvent,
};

use tempfile::NamedTempFile;

mod error;

pub type Result<T> = std::result::Result<T, error::Error>;

pub use error::Error;

pub fn monitor(
    audit_log: PathBuf,
    json: bool,
    //address: Vec<AddressStr>,
    ) -> Result<()> {

    use std::{thread, time};

    /*
    let mut stream = FileStream::new(&audit_log, OpenType::Open)?;
    let mut reader = BinaryReader::new(&mut stream, Endian::Big);
    reader.seek(AUDIT_IDENTITY.len())?;
    let mut deserializer = Deserializer { reader };

    let log_file = AuditLogFile::new(&audit_log)?;
    let mut it = log_file.iter()?;
    let mut count = it.count();
    */

    let mut file = File::open(&audit_log)?;

    let mut offset = audit_log.metadata()?.len();

    loop {
        let step = time::Duration::from_millis(100);
        thread::sleep(step);

        /*
        let len = audit_log.metadata()?.len();
        if len > offset {
            let mut temp = NamedTempFile::new()?;
            let mut temp_file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(temp.path())?;

            let byte_len = len - offset;
            let mut buffer = vec![0u8; byte_len as usize];
            file.read_exact(&mut buffer)?;

            temp.write_all(&AUDIT_IDENTITY)?;
            std::io::copy(&mut buffer.as_slice(), &mut temp_file)?;

            let changes = AuditLogFile::new(temp.path())?;
            let it = changes.iter()?;

            for record in it {
                let record = record?;
                println!("Got a new record {:#?}", record.value());
            }

            offset = audit_log.metadata()?.len();
        }
        */

        /*
        let it = log_file.iter()?;
        let it = it.skip(count);

        for record in it {
            println!("Got a new record...");
            let event = AuditLogFile::decode_row(&mut deserializer)?;
            print_event(event, json)?;
            count += 1;
        }
        */
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
        print_event(event, json)?;
    }

    Ok(())
}
