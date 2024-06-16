//! Types for the wire protocol.
mod common;
mod diff;
mod error;
mod patch;
mod scan;
mod sync;

pub use diff::{DiffRequest, DiffResponse};
pub use error::Error;
pub use patch::{PatchRequest, PatchResponse};
pub use scan::{ScanRequest, ScanResponse};

use crate::sdk::events::EventLogType;
use prost::{bytes::Buf, Message};

/// Result type for the wire protocol.
pub type Result<T> = std::result::Result<T, Error>;

/// Marker trait to indicate the inner type for protocol
/// type conversion.
trait WireConvert {
    type Inner: Message + Default;
}

/// Trait for wire protocol encoding and decoding.
pub trait WireEncodeDecode {
    /// Encode this request.
    fn encode(self) -> Result<Vec<u8>>;

    /// Decode this request.
    fn decode(buffer: impl Buf) -> Result<Self>
    where
        Self: Sized;
}

impl<T> WireEncodeDecode for T
where
    T: WireConvert,
    <T as WireConvert>::Inner: From<T>,
    T: TryFrom<<T as WireConvert>::Inner>,
    <T as TryFrom<<T as WireConvert>::Inner>>::Error: std::fmt::Debug,
{
    fn encode(self) -> Result<Vec<u8>> {
        let value: <Self as WireConvert>::Inner = self.into();
        Ok(encode(&value)?)
    }

    fn decode(buffer: impl Buf) -> Result<Self>
    where
        Self: Sized,
    {
        let result = decode::<<Self as WireConvert>::Inner>(buffer)?;
        // FIXME: do error conversion rather than unwrap
        Ok(result.try_into().unwrap())
    }
}

/// Encode a protobuf message.
fn encode(message: &impl Message) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    buf.reserve(message.encoded_len());
    message.encode(&mut buf)?;
    Ok(buf)
}

/// Decode a protobuf message.
pub fn decode<T: Default + Message>(buffer: impl Buf) -> Result<T> {
    Ok(T::decode(buffer)?)
}

fn decode_uuid(id: Option<Vec<u8>>) -> Result<uuid::Uuid> {
    let id: [u8; 16] = id.unwrap().as_slice().try_into()?;
    Ok(uuid::Uuid::from_bytes(id))
}

fn encode_uuid(id: uuid::Uuid) -> Option<Vec<u8>> {
    Some(id.as_bytes().to_vec())
}

fn into_event_log_type(
    wire_type: i32,
    folder_id: Option<Vec<u8>>,
) -> Result<EventLogType> {
    use std::io::{Error, ErrorKind};
    Ok(match wire_type {
        0 => EventLogType::Identity,
        1 => EventLogType::Account,
        #[cfg(feature = "device")]
        2 => EventLogType::Device,
        #[cfg(feature = "files")]
        3 => EventLogType::Files,
        4 => EventLogType::Folder(decode_uuid(folder_id)?),
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
        EventLogType::Folder(id) => (4, encode_uuid(id)),
    }
}
