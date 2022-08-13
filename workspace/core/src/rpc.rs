//! Types for remote procedure calls.
use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};
use std::collections::HashMap;
use crate::Error;

mod kinds {
    pub(super) const NOOP: u16 = 0;
    pub(super) const GET_WAL: u16 = 1;
}

/// Enumeration of available methods.
#[derive(Default, Debug, Eq, PartialEq)]
pub enum RequestMethod {
    #[default]
    Noop,
    /// Get the WAL log file.
    GetWal,
}

impl RequestMethod {
    /// Get the kind identifier for this request method.
    pub fn kind(&self) -> u16 {
        match self {
            RequestMethod::Noop => kinds::NOOP,
            RequestMethod::GetWal => kinds::GET_WAL,
        }
    }
}

impl TryFrom<u16> for RequestMethod {
    type Error = Error;
    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            kinds::GET_WAL => Ok(RequestMethod::GetWal),
            _ => {
                Err(Error::InvalidMethod(value))
            }
        }
    }
}

impl Encode for RequestMethod {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_u16(self.kind())?;
        Ok(())
    }
}

impl Decode for RequestMethod {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let kind = reader.read_u16()?;
        *self = kind.try_into().map_err(Box::from)?;
        Ok(())
    }
}

/// An RPC request message.
#[derive(Default, Debug, Eq, PartialEq)]
pub struct RequestMessage {
    method: RequestMethod,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl RequestMessage {
    /// Create a new request message.
    pub fn new(
        method: RequestMethod,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            method,
            headers,
            body,
        }
    }
}

impl Encode for RequestMessage {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        self.method.encode(&mut *writer)?;

        // Write headers
        writer.write_u32(self.headers.len() as u32)?;
        for (k, v) in self.headers.iter() {
            writer.write_string(k)?;
            writer.write_string(v)?;
        }

        // Write the body
        writer.write_u64(self.body.len() as u64)?;
        writer.write_bytes(&self.body)?;

        Ok(())
    }
}

impl Decode for RequestMessage {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let mut method: RequestMethod = Default::default();
        method.decode(&mut *reader)?;
        self.method = method;

        let mut headers = HashMap::new();
        let headers_len = reader.read_u32()?;
        for _ in 0..headers_len {
            let key = reader.read_string()?;
            let val = reader.read_string()?;
            headers.insert(key, val);
        }
        self.headers = headers;

        let body_len = reader.read_u64()?;
        let body = reader.read_bytes(body_len as usize)?;
        self.body = body;

        Ok(())
    }
}


/// An RPC response message.
#[derive(Default, Debug, Eq, PartialEq)]
pub struct ResponseMessage {
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl ResponseMessage {
    /// Create a new response message.
    pub fn new(headers: HashMap<String, String>, body: Vec<u8>) -> Self {
        Self { headers, body }
    }
}

impl Encode for ResponseMessage {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        // Write headers
        writer.write_u32(self.headers.len() as u32)?;
        for (k, v) in self.headers.iter() {
            writer.write_string(k)?;
            writer.write_string(v)?;
        }

        // Write the body
        writer.write_u64(self.body.len() as u64)?;
        writer.write_bytes(&self.body)?;

        Ok(())
    }
}

impl Decode for ResponseMessage {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let mut headers = HashMap::new();
        let headers_len = reader.read_u32()?;
        for _ in 0..headers_len {
            let key = reader.read_string()?;
            let val = reader.read_string()?;
            headers.insert(key, val);
        }
        self.headers = headers;

        let body_len = reader.read_u64()?;
        let body = reader.read_bytes(body_len as usize)?;
        self.body = body;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use crate::{encode, decode};
    
    #[test]
    fn rpc_encode() -> Result<()> {
        let mut headers = HashMap::new();
        headers.insert("X-Foo".to_owned(), "Bar".to_owned());
        let message = RequestMessage::new(
            RequestMethod::GetWal, headers, vec![0x0A, 0xFF]);

        let request = encode(&message)?;
        let decoded = decode(&request)?;

        assert_eq!(message, decoded);
        assert_eq!("Bar", decoded.headers.get("X-Foo").unwrap());
        assert_eq!(2, decoded.body.len());

        Ok(())
    }
}
