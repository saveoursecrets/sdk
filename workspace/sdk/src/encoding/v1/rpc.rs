use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};

use serde_json::Value;
use std::{
    borrow::Cow,
    io::{Read, Seek, Write},
};
use http::StatusCode;

use crate::{
    constants::RPC_IDENTITY,
    formats::FileIdentity,
    rpc::{Packet, Payload, RequestMessage, ResponseMessage},
    Error,
};

impl Encode for Packet<'_> {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        writer.write_bytes(RPC_IDENTITY)?;
        self.payload.encode(writer)?;
        Ok(())
    }
}

impl Decode for Packet<'_> {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        FileIdentity::read_identity(reader, &RPC_IDENTITY)
            .map_err(Box::from)?;
        let mut payload: Payload<'_> = Default::default();
        payload.decode(reader)?;
        self.payload = payload;
        Ok(())
    }
}

impl Encode for Payload<'_> {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
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
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
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

impl Encode for RequestMessage<'_> {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
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
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
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

impl Encode for ResponseMessage<'_> {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
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
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
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
                self.result = Some(Err(Error::RpcError(err_msg)))
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
