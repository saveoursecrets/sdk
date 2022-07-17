//! Messages sent between the client and server.

use binary_stream::{
    BinaryError, BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
    Endian, MemoryStream,
};
use sos_core::constants::AGENT_IDENTITY;

use super::{Error, Result};

const KEY_SIZE: usize = 20;
const VALUE_SIZE: usize = 32;

/// Key type for requests and storage.
pub type Key = [u8; KEY_SIZE];

/// Value type for storage.
pub type Value = [u8; VALUE_SIZE];

const GET: u8 = 0x01;
const SET: u8 = 0x02;

/// Request messages sent to the key agent server.
#[derive(Debug, PartialEq, Eq)]
pub enum AgentRequest {
    /// Try to get a key.
    Get(Key),
    /// Try to set a key.
    Set(Key, Value),
}

impl Default for AgentRequest {
    fn default() -> Self {
        Self::Get([0u8; KEY_SIZE])
    }
}

impl AgentRequest {
    /// Encode a payload.
    pub fn encode(request: AgentRequest) -> Result<Vec<u8>> {
        let mut stream = MemoryStream::new();
        let mut writer = BinaryWriter::new(&mut stream, Endian::Big);
        request.encode(&mut writer)?;
        Ok(stream.into())
    }

    /// Decode a payload.
    pub fn decode(buffer: Vec<u8>) -> Result<Self> {
        let mut stream: MemoryStream = buffer.into();
        let mut reader = BinaryReader::new(&mut stream, Endian::Big);
        let mut request: AgentRequest = Default::default();
        request.decode(&mut reader)?;
        Ok(request)
    }
}

impl Encode for AgentRequest {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_bytes(&AGENT_IDENTITY)?;

        // Must encode the size for the server to know
        // how many bytes to read
        let size = match self {
            Self::Get(_) => 21,
            Self::Set(_, _) => 53,
        };
        writer.write_u32(size)?;

        let kind = match self {
            Self::Get(_) => GET,
            Self::Set(_, _) => SET,
        };

        writer.write_u8(kind)?;
        match self {
            Self::Get(key) => {
                writer.write_bytes(&key)?;
            }
            Self::Set(key, value) => {
                writer.write_bytes(&key)?;
                writer.write_bytes(&value)?;
            }
        }

        Ok(())
    }
}

impl Decode for AgentRequest {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let kind = reader.read_u8()?;

        match kind {
            GET => {
                let key: Key =
                    reader.read_bytes(KEY_SIZE)?.as_slice().try_into()?;
                *self = AgentRequest::Get(key);
            }
            SET => {
                let key: Key =
                    reader.read_bytes(KEY_SIZE)?.as_slice().try_into()?;
                let value: Value =
                    reader.read_bytes(VALUE_SIZE)?.as_slice().try_into()?;
                *self = AgentRequest::Set(key, value);
            }
            _ => {
                return Err(BinaryError::Boxed(Box::new(
                    Error::InvalidMessageKind(kind),
                )))
            }
        }
        Ok(())
    }
}

/// Response message received from the key agent server.
#[derive(Default, Debug, PartialEq, Eq)]
pub enum AgentResponse {
    /// Response to a call to set a key.
    #[default]
    Set,
    /// Response to a call to get a key.
    Get(Option<Value>),
}

impl AgentResponse {
    /// Encode a payload.
    pub fn encode(response: AgentResponse) -> Result<Vec<u8>> {
        let mut stream = MemoryStream::new();
        let mut writer = BinaryWriter::new(&mut stream, Endian::Big);
        response.encode(&mut writer)?;
        let buffer: Vec<u8> = stream.into();
        Ok(buffer)
    }

    /// Decode a payload.
    pub fn decode(buffer: Vec<u8>) -> Result<Self> {
        let mut stream: MemoryStream = buffer.into();
        let mut reader = BinaryReader::new(&mut stream, Endian::Big);
        let mut response: AgentResponse = Default::default();
        response.decode(&mut reader)?;
        Ok(response)
    }
}

impl Encode for AgentResponse {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_bytes(&AGENT_IDENTITY)?;

        // Must encode the size for the client to know
        // how many bytes to read
        let size = match self {
            Self::Get(value) => {
                if value.is_some() {
                    34
                } else {
                    2
                }
            }
            Self::Set => 1,
        };
        writer.write_u32(size)?;

        let kind = match self {
            Self::Get(_) => GET,
            Self::Set => SET,
        };

        writer.write_u8(kind)?;
        match self {
            Self::Get(value) => {
                writer.write_bool(value.is_some())?;
                if let Some(value) = &value {
                    writer.write_bytes(value)?;
                }
            }
            Self::Set => {}
        }

        Ok(())
    }
}

impl Decode for AgentResponse {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let kind = reader.read_u8()?;
        match kind {
            GET => {
                let has_value = reader.read_bool()?;
                let value = if has_value {
                    let value: Value = reader
                        .read_bytes(VALUE_SIZE)?
                        .as_slice()
                        .try_into()?;
                    Some(value)
                } else {
                    None
                };
                *self = AgentResponse::Get(value);
            }
            SET => {
                *self = AgentResponse::Set;
            }
            _ => {
                return Err(BinaryError::Boxed(Box::new(
                    Error::InvalidMessageKind(kind),
                )))
            }
        }
        Ok(())
    }
}
