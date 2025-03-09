use crate::ed25519::BinaryEd25519Signature;
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use sos_core::encoding::encoding_error;
use std::io::Result;
use tokio::io::{AsyncRead, AsyncSeek, AsyncWrite};

#[async_trait]
impl Encodable for BinaryEd25519Signature {
    async fn encode<W: AsyncWrite + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> Result<()> {
        // 64 byte signature
        writer.write_bytes(self.0.to_bytes()).await?;
        Ok(())
    }
}

#[async_trait]
impl Decodable for BinaryEd25519Signature {
    async fn decode<R: AsyncRead + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> Result<()> {
        use ed25519_dalek::Signature;
        let buffer: [u8; Signature::BYTE_SIZE] = reader
            .read_bytes(Signature::BYTE_SIZE)
            .await?
            .as_slice()
            .try_into()
            .map_err(encoding_error)?;
        self.0 = buffer.into();
        Ok(())
    }
}
