use http::StatusCode;
use serde_json::Value;
use std::{borrow::Cow, io::Result};

use sos_sdk::{
    constants::RPC_IDENTITY, encoding::encoding_error, formats::FileIdentity,
};

use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};

use crate::rpc::{Error, Packet, Payload, RequestMessage, ResponseMessage};

#[async_trait]
impl Encodable for Packet<'_> {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        writer.write_bytes(RPC_IDENTITY).await?;
        self.payload.encode(writer).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for Packet<'_> {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        FileIdentity::read_identity(reader, &RPC_IDENTITY)
            .await
            .map_err(encoding_error)?;
        let mut payload: Payload<'_> = Default::default();
        payload.decode(reader).await?;
        self.payload = payload;
        Ok(())
    }
}

#[async_trait]
impl Encodable for Payload<'_> {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        let is_response = matches!(self, Payload::Response(_));
        writer.write_bool(is_response).await?;
        match self {
            Payload::Request(val) => val.encode(writer).await?,
            Payload::Response(val) => val.encode(writer).await?,
            _ => panic!("attempt to encode noop RPC payload"),
        }
        Ok(())
    }
}

#[async_trait]
impl Decodable for Payload<'_> {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let is_response = reader.read_bool().await?;
        *self = if is_response {
            let mut response: ResponseMessage<'_> = Default::default();
            response.decode(reader).await?;
            Payload::Response(response)
        } else {
            let mut request: RequestMessage<'_> = Default::default();
            request.decode(reader).await?;
            Payload::Request(request)
        };
        Ok(())
    }
}

#[async_trait]
impl Encodable for RequestMessage<'_> {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        // Id
        writer.write_bool(self.id.is_some()).await?;
        if let Some(id) = &self.id {
            writer.write_u64(id).await?;
        }

        // Method
        writer.write_string(self.method.as_ref()).await?;

        // Parameters
        let params =
            serde_json::to_vec(&self.parameters).map_err(encoding_error)?;
        writer.write_u32(params.len() as u32).await?;
        writer.write_bytes(&params).await?;

        // Body
        writer.write_u64(self.body.len() as u64).await?;
        writer.write_bytes(self.body.as_ref()).await?;

        Ok(())
    }
}

#[async_trait]
impl Decodable for RequestMessage<'_> {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        // Id
        let has_id = reader.read_bool().await?;
        if has_id {
            self.id = Some(reader.read_u64().await?);
        }

        // Method
        self.method = Cow::Owned(reader.read_string().await?);

        // Parameters
        let params_len = reader.read_u32().await?;
        let params = reader.read_bytes(params_len as usize).await?;
        self.parameters =
            serde_json::from_slice(&params).map_err(encoding_error)?;

        // Body
        let body_len = reader.read_u64().await?;
        let body = reader.read_bytes(body_len as usize).await?;
        self.body = Cow::Owned(body);

        Ok(())
    }
}

#[async_trait]
impl Encodable for ResponseMessage<'_> {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        // Id
        writer.write_bool(self.id.is_some()).await?;
        if let Some(id) = &self.id {
            writer.write_u64(id).await?;
        }

        // Result
        writer.write_bool(self.result.is_some()).await?;
        if let Some(result) = &self.result {
            let status: u16 = self.status.into();
            writer.write_u16(status).await?;
            match result {
                Ok(value) => {
                    writer.write_bool(false).await?;
                    let result =
                        serde_json::to_vec(value).map_err(encoding_error)?;
                    writer.write_u32(result.len() as u32).await?;
                    writer.write_bytes(&result).await?;
                }
                Err(e) => {
                    writer.write_bool(true).await?;
                    writer.write_string(e.to_string()).await?;
                }
            }
        }

        // Body
        writer.write_u64(self.body.len() as u64).await?;
        writer.write_bytes(self.body.as_ref()).await?;

        Ok(())
    }
}

#[async_trait]
impl Decodable for ResponseMessage<'_> {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        // Id
        let has_id = reader.read_bool().await?;
        if has_id {
            self.id = Some(reader.read_u64().await?);
        }

        // Result
        let has_result = reader.read_bool().await?;

        if has_result {
            self.status = StatusCode::from_u16(reader.read_u16().await?)
                .map_err(encoding_error)?;
            let has_error = reader.read_bool().await?;

            if has_error {
                let err_msg = reader.read_string().await?;
                self.result = Some(Err(Error::RpcError(err_msg)))
            } else {
                let value_len = reader.read_u32().await?;

                let value = reader.read_bytes(value_len as usize).await?;
                let value: Value =
                    serde_json::from_slice(&value).map_err(encoding_error)?;
                self.result = Some(Ok(value))
            }
        }

        // Body
        let body_len = reader.read_u64().await?;
        let body = reader.read_bytes(body_len as usize).await?;
        self.body = Cow::Owned(body);

        Ok(())
    }
}
