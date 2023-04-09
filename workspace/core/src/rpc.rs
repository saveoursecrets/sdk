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
use http::StatusCode;
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
        writer.write_bytes(RPC_IDENTITY)?;
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
    #[doc(hidden)]
    #[default]
    Noop,
    /// Request payload.
    Request(RequestMessage<'a>),
    /// Response payload.
    Response(ResponseMessage<'a>),
}

impl Encode for Payload<'_> {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        let is_response = matches!(self, Payload::Response(_));
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
    /// Create a new request message with a body.
    pub fn new<T>(
        id: Option<u64>,
        method: &'a str,
        parameters: T,
        body: Cow<'a, [u8]>,
    ) -> Result<Self>
    where
        T: Serialize,
    {
        Ok(Self {
            id,
            method: Cow::Borrowed(method),
            parameters: serde_json::to_value(parameters)?,
            body,
        })
    }

    /// Create a new request message without a body.
    pub fn new_call<T>(
        id: Option<u64>,
        method: &'a str,
        parameters: T,
    ) -> Result<Self>
    where
        T: Serialize,
    {
        RequestMessage::new(id, method, parameters, Cow::Owned(vec![]))
    }

    /// Get the message identifier.
    pub fn id(&self) -> Option<u64> {
        self.id
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

impl From<RequestMessage<'_>> for Vec<u8> {
    fn from(value: RequestMessage<'_>) -> Self {
        value.body.into_owned()
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

/// Result that can be extracted from a response message.
///
/// Contains the message id, HTTP status code, a possible result
/// and the message body.
pub type ResponseResult<T> =
    (Option<u64>, StatusCode, Option<Result<T>>, Vec<u8>);

/// An RPC response message.
#[derive(Default, Debug)]
pub struct ResponseMessage<'a> {
    id: Option<u64>,
    status: StatusCode,
    result: Option<Result<Value>>,
    body: Cow<'a, [u8]>,
}

impl<'a> ResponseMessage<'a> {
    /// Create a new response message.
    pub fn new<T>(
        id: Option<u64>,
        status: StatusCode,
        result: Option<Result<T>>,
        body: Cow<'a, [u8]>,
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
            status,
            result,
            body,
        })
    }

    /// Create a new response message with an empty body.
    pub fn new_reply<T>(
        id: Option<u64>,
        status: StatusCode,
        result: Option<Result<T>>,
    ) -> Result<Self>
    where
        T: Serialize,
    {
        ResponseMessage::new(id, status, result, Cow::Owned(vec![]))
    }

    /// Get the message identifier.
    pub fn id(&self) -> Option<u64> {
        self.id
    }

    /// Get the status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Take the result.
    pub fn take<T: DeserializeOwned>(self) -> Result<ResponseResult<T>> {
        let value = if let Some(result) = self.result {
            match result {
                Ok(value) => Some(Ok(serde_json::from_value::<T>(value)?)),
                Err(e) => Some(Err(e)),
            }
        } else {
            None
        };
        Ok((self.id, self.status, value, self.body.to_vec()))
    }
}

impl From<ResponseMessage<'_>> for Vec<u8> {
    fn from(value: ResponseMessage<'_>) -> Self {
        value.body.into_owned()
    }
}

impl Encode for ResponseMessage<'_> {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        // Id
        writer.write_bool(self.id.is_some())?;
        if let Some(id) = &self.id {
            writer.write_u64(id)?;
        }

        // Result
        writer.write_bool(self.result.is_some())?;
        if let Some(result) = &self.result {
            let status: u16 = self.status.into();
            writer.write_u16(status)?;
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
        let has_id = reader.read_bool()?;
        if has_id {
            self.id = Some(reader.read_u64()?);
        }

        // Result
        let has_result = reader.read_bool()?;

        if has_result {
            self.status = StatusCode::from_u16(reader.read_u16()?)
                .map_err(Box::from)?;
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

impl From<Error> for ResponseMessage<'_> {
    fn from(value: Error) -> Self {
        ResponseMessage::new_reply::<()>(
            None,
            StatusCode::INTERNAL_SERVER_ERROR,
            Some(Err(value)),
        )
        .expect("failed to encode error response message")
    }
}

// NOTE: if we put the id first the compiler complains about a conflict
// NOTE: with a TryFrom implementation
impl From<(StatusCode, Option<u64>)> for ResponseMessage<'_> {
    fn from(value: (StatusCode, Option<u64>)) -> Self {
        let message = value
            .0
            .canonical_reason()
            .map(|s| s.to_owned())
            .unwrap_or_else(|| "unexpected status code".to_owned());

        ResponseMessage::new_reply::<()>(
            value.1,
            value.0,
            Some(Err(Error::Message(message))),
        )
        .expect("failed to encode error response message")
    }
}

impl<'a, T: Serialize> TryFrom<(StatusCode, Option<u64>, T)>
    for ResponseMessage<'a>
{
    type Error = Error;

    fn try_from(value: (StatusCode, Option<u64>, T)) -> Result<Self> {
        let reply =
            ResponseMessage::new_reply(value.1, value.0, Some(Ok(value.2)))?;
        Ok(reply)
    }
}

impl<'a, T: Serialize> TryFrom<(Option<u64>, T)> for ResponseMessage<'a> {
    type Error = Error;

    fn try_from(value: (Option<u64>, T)) -> Result<Self> {
        let reply = ResponseMessage::new_reply(
            value.0,
            StatusCode::OK,
            Some(Ok(value.1)),
        )?;
        Ok(reply)
    }
}

/// Trait for implementations that process incoming requests.
#[async_trait]
pub trait Service {
    /// State for this service.
    type State: Send + Sync;

    /// Handle an incoming message.
    async fn handle<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> Result<ResponseMessage<'a>>;

    /// Serve an incoming request.
    async fn serve<'a>(
        &self,
        state: Self::State,
        request: RequestMessage<'a>,
    ) -> Option<ResponseMessage<'a>> {
        match self.handle(state, request).await {
            Ok(res) => {
                if res.id().is_some() {
                    Some(res)
                } else {
                    None
                }
            }
            Err(e) => {
                let reply: ResponseMessage<'_> = e.into();
                Some(reply)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{decode, encode};
    use anyhow::Result;
    use http::StatusCode;

    #[test]
    fn rpc_encode() -> Result<()> {
        let body = vec![0x0A, 0xFF];
        let message =
            RequestMessage::new(Some(1), "GetWal", (), Cow::Borrowed(&body))?;

        let request = encode(&message)?;
        let decoded: RequestMessage = decode(&request)?;

        assert_eq!(message.method(), decoded.method());
        //assert_eq!((), decoded.parameters::<()>()?);
        assert_eq!(&body, decoded.body());

        let result = Some(Ok("Foo".to_owned()));
        let reply = ResponseMessage::new(
            Some(1),
            StatusCode::OK,
            result,
            Cow::Borrowed(&body),
        )?;

        let response = encode(&reply)?;
        let decoded: ResponseMessage = decode(&response)?;

        let result = decoded.take::<String>()?;
        let value = result.2.unwrap().unwrap();

        assert_eq!(Some(1), result.0);
        assert_eq!("Foo", &value);
        assert_eq!(body, result.3);

        // Check the packet request encoding
        let req = Packet::new_request(message);
        let enc = encode(&req)?;
        let pkt: Packet<'_> = decode(&enc)?;

        let incoming: RequestMessage<'_> = pkt.try_into()?;
        assert_eq!(Some(1u64), incoming.id());
        assert_eq!("GetWal", incoming.method());
        //assert_eq!((), incoming.parameters::<()>()?);
        assert_eq!(&body, incoming.body());

        // Check the packet response encoding
        let res = Packet::new_response(reply);
        let enc = encode(&res)?;
        let pkt: Packet<'_> = decode(&enc)?;

        let incoming: ResponseMessage<'_> = pkt.try_into()?;
        let result = incoming.take::<String>()?;
        let value = result.2.unwrap().unwrap();
        assert_eq!(Some(1), result.0);
        assert_eq!("Foo", &value);
        assert_eq!(body, result.3);

        Ok(())
    }
}
