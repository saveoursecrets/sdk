//! Messages sent between the client and server.

use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode, Endian,
    MemoryStream,
};
use sos_core::{constants::AGENT_IDENTITY, FileIdentity};

use super::Result;

/// Request messages sent over the IPC channel.
#[derive(Debug)]
pub struct AgentRequest(pub(crate) Vec<u8>);

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
        Ok(AgentRequest(buffer))
    }
}

impl Encode for AgentRequest {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_bytes(&AGENT_IDENTITY)?;
        writer.write_u32(self.0.len() as u32)?;
        writer.write_bytes(&self.0)?;
        Ok(())
    }
}

impl Decode for AgentRequest {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let len = reader.read_u32()?;
        self.0 = reader.read_bytes(len as usize)?;
        Ok(())
    }
}

/// Response messages sent over the IPC channel.
#[derive(Debug)]
pub struct AgentResponse(pub(crate) Vec<u8>);

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
        Ok(AgentResponse(buffer))
    }
}

impl Encode for AgentResponse {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_bytes(&AGENT_IDENTITY)?;
        writer.write_u32(self.0.len() as u32)?;
        writer.write_bytes(&self.0)?;
        Ok(())
    }
}

impl Decode for AgentResponse {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let len = reader.read_u32()?;
        self.0 = reader.read_bytes(len as usize)?;
        Ok(())
    }
}
