//! Types for binary remote procedure calls.
//!
//! Message identifiers have the same semantics as JSON-RPC;
//! if a request does not have an `id` than no reply is expected
//! otherwise a service must reply.
use crate::{
    constants::RPC_IDENTITY, file_identity::FileIdentity, Error, Result,
};
use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::borrow::Cow;

use async_trait::async_trait;

/// Packet including identity bytes.
#[derive(Default)]
pub struct Packet<'a> {
    payload: Payload<'a>,
}

impl<'a> Packet<'a> {
    /// Create a new request packet.
    pub fn new_request(message: RequestMessage<'a>) -> Self {
        Self {
            payload: Payload::Request(message),
        }
    }

    /// Create a new response packet.
    pub fn new_response(message: ResponseMessage<'a>) -> Self {
        Self {
            payload: Payload::Response(message),
        }
    }
}

impl<'a> TryFrom<Packet<'a>> for RequestMessage<'a> {
    type Error = Error;
    fn try_from(packet: Packet<'a>) -> Result<Self> {
        match packet.payload {
            Payload::Request(val) => Ok(val),
            _ => Err(Error::Message("expected a request payload".to_owned())),
        }
    }
}

impl<'a> TryFrom<Packet<'a>> for ResponseMessage<'a> {
    type Error = Error;
    fn try_from(packet: Packet<'a>) -> Result<Self> {
        match packet.payload {
            Payload::Response(val) => Ok(val),
            _ => {
                Err(Error::Message("expected a response payload".to_owned()))
            }
        }
    }
}

impl Encode for Packet<'_> {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        writer.write_bytes(&RPC_IDENTITY)?;
        self.payload.encode(writer)?;
        Ok(())
    }
}

impl Decode for Packet<'_> {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        FileIdentity::read_identity(reader, &RPC_IDENTITY)
            .map_err(Box::from)?;
        let mut payload: Payload<'_> = Default::default();
        payload.decode(reader)?;
        self.payload = payload;
        Ok(())
    }
}

/// Payload for a packet; either a request or response.
#[derive(Default)]
pub enum Payload<'a> {
    /// Default variant.
    #[default]
    Noop,
    /// Request payload.
    Request(RequestMessage<'a>),
    /// Response payload.
    Response(ResponseMessage<'a>),
}

impl Encode for Payload<'_> {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        let is_response = if let Payload::Response(_) = self {
            true
        } else {
            false
        };
        writer.write_bool(is_response)?;
        match self {
            Payload::Request(val) => val.encode(writer)?,
            Payload::Response(val) => val.encode(writer)?,
            _ => panic!("attempt to encode noop RPC payload"),
        }
        Ok(())
    }
}

impl Decode for Payload<'_> {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let is_response = reader.read_bool()?;
        *self = if is_response {
            let mut response: ResponseMessage<'_> = Default::default();
            response.decode(reader)?;
            Payload::Response(response)
        } else {
            let mut request: RequestMessage<'_> = Default::default();
            request.decode(reader)?;
            Payload::Request(request)
        };
        Ok(())
    }
}

/// An RPC request message.
#[derive(Default, Debug)]
pub struct RequestMessage<'a> {
    id: Option<u64>,
    method: Cow<'a, str>,
    parameters: Value,
    body: Cow<'a, [u8]>,
}

impl<'a> RequestMessage<'a> {
    /// Create a new request message.
    pub fn new<T>(
        id: Option<u64>,
        method: &'a str,
        parameters: T,
        body: &'a [u8],
    ) -> Result<Self>
    where
        T: Serialize,
    {
        Ok(Self {
            id,
            method: Cow::Borrowed(method),
            parameters: serde_json::to_value(parameters)?,
            body: Cow::Borrowed(body),
        })
    }

    /// Get the message identifier.
    pub fn id(&self) -> Option<&u64> {
        self.id.as_ref()
    }

    /// Get the method name.
    pub fn method(&self) -> &str {
        self.method.as_ref()
    }

    /// Get the method parameters as type `T`.
    pub fn parameters<T: DeserializeOwned>(&self) -> Result<T> {
        Ok(serde_json::from_value::<T>(self.parameters.clone())?)
    }

    /// Get a slice of the message body.
    pub fn body(&self) -> &[u8] {
        self.body.as_ref()
    }
}

impl Encode for RequestMessage<'_> {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        // Id
        writer.write_bool(self.id.is_some())?;
        if let Some(id) = &self.id {
            writer.write_u64(id)?;
        }

        // Method
        writer.write_string(self.method.as_ref())?;

        // Parameters
        let params =
            serde_json::to_vec(&self.parameters).map_err(Box::from)?;
        writer.write_u32(params.len() as u32)?;
        writer.write_bytes(&params)?;

        // Body
        writer.write_u64(self.body.len() as u64)?;
        writer.write_bytes(self.body.as_ref())?;

        Ok(())
    }
}

impl Decode for RequestMessage<'_> {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        // Id
        let has_id = reader.read_bool()?;
        if has_id {
            self.id = Some(reader.read_u64()?);
        }

        // Method
        self.method = Cow::Owned(reader.read_string()?);

        // Parameters
        let params_len = reader.read_u32()?;
        let params = reader.read_bytes(params_len as usize)?;
        self.parameters =
            serde_json::from_slice(&params).map_err(Box::from)?;

        // Body
        let body_len = reader.read_u64()?;
        let body = reader.read_bytes(body_len as usize)?;
        self.body = Cow::Owned(body);

        Ok(())
    }
}

/// An RPC response message.
#[derive(Default, Debug)]
pub struct ResponseMessage<'a> {
    id: u64,
    result: Option<Result<Value>>,
    body: Cow<'a, [u8]>,
}

impl<'a> ResponseMessage<'a> {
    /// Create a new response message.
    pub fn new<T>(
        id: u64,
        result: Option<Result<T>>,
        body: &'a [u8],
    ) -> Result<Self>
    where
        T: Serialize,
    {
        let result = match result {
            Some(value) => match value {
                Ok(value) => Some(Ok(serde_json::to_value(value)?)),
                Err(e) => Some(Err(e)),
            },
            None => None,
        };

        Ok(Self {
            id,
            result,
            body: Cow::Borrowed(body),
        })
    }

    /// Get the message identifier.
    pub fn id(&self) -> &u64 {
        &self.id
    }

    /// Take the result.
    pub fn take<T: DeserializeOwned>(
        self,
    ) -> Result<(u64, Option<Result<T>>, Vec<u8>)> {
        let value = if let Some(result) = self.result {
            match result {
                Ok(value) => Some(Ok(serde_json::from_value::<T>(value)?)),
                Err(e) => Some(Err(e)),
            }
        } else {
            None
        };
        Ok((self.id, value, self.body.to_vec()))
    }
}

impl Encode for ResponseMessage<'_> {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        // Id
        writer.write_u64(&self.id)?;

        // Result
        writer.write_bool(self.result.is_some())?;
        if let Some(result) = &self.result {
            match result {
                Ok(value) => {
                    writer.write_bool(false)?;
                    let result =
                        serde_json::to_vec(value).map_err(Box::from)?;

                    writer.write_u32(result.len() as u32)?;
                    writer.write_bytes(&result)?;
                }
                Err(e) => {
                    writer.write_bool(true)?;
                    writer.write_string(e.to_string())?;
                }
            }
        }

        // Body
        writer.write_u64(self.body.len() as u64)?;
        writer.write_bytes(self.body.as_ref())?;

        Ok(())
    }
}

impl Decode for ResponseMessage<'_> {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        // Id
        self.id = reader.read_u64()?;

        // Result
        let has_result = reader.read_bool()?;

        if has_result {
            let has_error = reader.read_bool()?;

            if has_error {
                let err_msg = reader.read_string()?;
                self.result = Some(Err(Error::Message(err_msg)))
            } else {
                let value_len = reader.read_u32()?;

                let value = reader.read_bytes(value_len as usize)?;
                let value: Value =
                    serde_json::from_slice(&value).map_err(Box::from)?;
                self.result = Some(Ok(value))
            }
        }

        // Body
        let body_len = reader.read_u64()?;
        let body = reader.read_bytes(body_len as usize)?;
        self.body = Cow::Owned(body);

        Ok(())
    }
}

/// Trait for implementations that process incoming requests.
#[async_trait]
pub trait Service {
    /// State for this service.
    type State;

    /// Handle an incoming message.
    fn handle<'a>(
        &self,
        state: &Self::State,
        request: RequestMessage<'a>,
    ) -> Result<Option<ResponseMessage<'a>>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode, encode};
    use anyhow::Result;

    #[test]
    fn rpc_encode() -> Result<()> {
        let body = vec![0x0A, 0xFF];
        let message = RequestMessage::new(Some(1), "GetWal", (), &body)?;

        let request = encode(&message)?;
        let decoded: RequestMessage = decode(&request)?;

        assert_eq!(message.method(), decoded.method());
        assert_eq!((), decoded.parameters::<()>()?);
        assert_eq!(&body, decoded.body());

        let result = Some(Ok("Foo".to_owned()));
        let reply = ResponseMessage::new(1, result, &body)?;

        let response = encode(&reply)?;
        let decoded: ResponseMessage = decode(&response)?;

        let result = decoded.take::<String>()?;
        let value = result.1.unwrap().unwrap();

        assert_eq!(1, result.0);
        assert_eq!("Foo", &value);
        assert_eq!(body, result.2);

        // Check the packet request encoding
        let req = Packet::new_request(message);
        let enc = encode(&req)?;
        let pkt: Packet<'_> = decode(&enc)?;

        let incoming: RequestMessage<'_> = pkt.try_into()?;
        assert_eq!(Some(&1u64), incoming.id());
        assert_eq!("GetWal", incoming.method());
        assert_eq!((), incoming.parameters::<()>()?);
        assert_eq!(&body, incoming.body());

        // Check the packet response encoding
        let res = Packet::new_response(reply);
        let enc = encode(&res)?;
        let pkt: Packet<'_> = decode(&enc)?;

        let incoming: ResponseMessage<'_> = pkt.try_into()?;
        let result = incoming.take::<String>()?;
        let value = result.1.unwrap().unwrap();
        assert_eq!(1, result.0);
        assert_eq!("Foo", &value);
        assert_eq!(body, result.2);

        Ok(())
    }
}
