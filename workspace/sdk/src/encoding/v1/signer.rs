use crate::{encoding::encoding_error, signer::ecdsa::BinarySignature};
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::Result;

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encodable for BinarySignature {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        // 65 byte signature
        let buffer = self.0.to_bytes();
        writer.write_bytes(buffer).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decodable for BinarySignature {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        let buffer: [u8; 65] = reader
            .read_bytes(65)
            .await?
            .as_slice()
            .try_into()
            .map_err(encoding_error)?;
        self.0 = buffer.into();
        Ok(())
    }
}
