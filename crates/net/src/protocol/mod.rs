//! Types for the wire protocol.
mod common;
mod diff;
mod patch;
mod scan;
mod sync;

pub use diff::{DiffRequest, DiffResponse};
pub use patch::{PatchRequest, PatchResponse};
pub use scan::{ScanRequest, ScanResponse};

use crate::sdk::{events::EventLogType, vault::VaultId, Result};
use prost::{bytes::Buf, Message};
use std::io::{Error, ErrorKind};

/// Encode a protobuf message.
fn encode(message: &impl Message) -> crate::Result<Vec<u8>> {
    let mut buf = Vec::new();
    buf.reserve(message.encoded_len());
    message.encode(&mut buf)?;
    Ok(buf)
}

/// Decode a protobuf message.
pub fn decode<T: Default + Message>(buffer: impl Buf) -> crate::Result<T> {
    Ok(T::decode(buffer)?)
}

fn into_event_log_type(
    wire_type: i32,
    folder_id: Option<String>,
) -> Result<EventLogType> {
    Ok(match wire_type {
        0 => EventLogType::Identity,
        1 => EventLogType::Account,
        #[cfg(feature = "device")]
        2 => EventLogType::Device,
        #[cfg(feature = "files")]
        3 => EventLogType::Files,
        4 => {
            let folder_id = folder_id.unwrap();
            let folder_id: VaultId = folder_id.parse()?;
            EventLogType::Folder(folder_id)
        }
        _ => {
            return Err(Error::new(
                ErrorKind::Other,
                format!("unsupported wire event log type {}", wire_type),
            )
            .into());
        }
    })
}

fn into_wire_event_log_type(log_type: EventLogType) -> (i32, Option<String>) {
    match log_type {
        EventLogType::Identity => (0, None),
        EventLogType::Account => (1, None),
        #[cfg(feature = "device")]
        EventLogType::Device => (2, None),
        #[cfg(feature = "files")]
        EventLogType::Files => (3, None),
        EventLogType::Folder(id) => (4, Some(id.to_string())),
    }
}
