//! Types for the wire protocol.
mod common;
mod diff;
mod patch;
mod scan;
mod sync;

pub use diff::{DiffRequest, DiffResponse};
pub use patch::{PatchRequest, PatchResponse};
pub use scan::{ScanRequest, ScanResponse};

use crate::sdk::{events::EventLogType, Result};
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
    folder_id: Option<Vec<u8>>,
) -> Result<EventLogType> {
    Ok(match wire_type {
        0 => EventLogType::Identity,
        1 => EventLogType::Account,
        #[cfg(feature = "device")]
        2 => EventLogType::Device,
        #[cfg(feature = "files")]
        3 => EventLogType::Files,
        4 => {
            let folder_id: [u8; 16] =
                folder_id.unwrap().as_slice().try_into()?;
            EventLogType::Folder(uuid::Uuid::from_bytes(folder_id))
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

fn into_wire_event_log_type(
    log_type: EventLogType,
) -> (i32, Option<Vec<u8>>) {
    match log_type {
        EventLogType::Identity => (0, None),
        EventLogType::Account => (1, None),
        #[cfg(feature = "device")]
        EventLogType::Device => (2, None),
        #[cfg(feature = "files")]
        EventLogType::Files => (3, None),
        EventLogType::Folder(id) => (4, Some(id.as_bytes().to_vec())),
    }
}
