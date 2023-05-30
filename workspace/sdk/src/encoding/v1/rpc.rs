use http::StatusCode;
use serde_json::Value;
use std::borrow::Cow;

use crate::{
    constants::RPC_IDENTITY,
    formats::FileIdentity,
    rpc::{Packet, Payload, RequestMessage, ResponseMessage},
    Error,
};

use tokio::io::{AsyncReadExt, AsyncSeek, AsyncWriteExt};

use async_trait::async_trait;
use binary_stream::{
    tokio::{BinaryReader, BinaryWriter, Decode, Encode},
    BinaryResult,
};

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for Packet<'_> {
    async fn encode<W: AsyncWriteExt + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        writer.write_bytes(RPC_IDENTITY).await?;
        self.payload.encode(writer).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for Packet<'_> {
    async fn decode<R: AsyncReadExt + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        FileIdentity::read_identity(reader, &RPC_IDENTITY)
            .await
            .map_err(Box::from)?;
        let mut payload: Payload<'_> = Default::default();
        payload.decode(reader).await?;
        self.payload = payload;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for Payload<'_> {
    async fn encode<W: AsyncWriteExt + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for Payload<'_> {
    async fn decode<R: AsyncReadExt + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for RequestMessage<'_> {
    async fn encode<W: AsyncWriteExt + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        // Id
        writer.write_bool(self.id.is_some()).await?;
        if let Some(id) = &self.id {
            writer.write_u64(id).await?;
        }

        // Method
        writer.write_string(self.method.as_ref()).await?;

        // Parameters
        let params =
            serde_json::to_vec(&self.parameters).map_err(Box::from)?;
        writer.write_u32(params.len() as u32).await?;
        writer.write_bytes(&params).await?;

        // Body
        writer.write_u64(self.body.len() as u64).await?;
        writer.write_bytes(self.body.as_ref()).await?;

        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for RequestMessage<'_> {
    async fn decode<R: AsyncReadExt + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
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
            serde_json::from_slice(&params).map_err(Box::from)?;

        // Body
        let body_len = reader.read_u64().await?;
        let body = reader.read_bytes(body_len as usize).await?;
        self.body = Cow::Owned(body);

        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for ResponseMessage<'_> {
    async fn encode<W: AsyncWriteExt + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
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
                        serde_json::to_vec(value).map_err(Box::from)?;
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for ResponseMessage<'_> {
    async fn decode<R: AsyncReadExt + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        // Id
        let has_id = reader.read_bool().await?;
        if has_id {
            self.id = Some(reader.read_u64().await?);
        }

        // Result
        let has_result = reader.read_bool().await?;

        if has_result {
            self.status = StatusCode::from_u16(reader.read_u16().await?)
                .map_err(Box::from)?;
            let has_error = reader.read_bool().await?;

            if has_error {
                let err_msg = reader.read_string().await?;
                self.result = Some(Err(Error::RpcError(err_msg)))
            } else {
                let value_len = reader.read_u32().await?;

                let value = reader.read_bytes(value_len as usize).await?;
                let value: Value =
                    serde_json::from_slice(&value).map_err(Box::from)?;
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
