use crate::{
    encoding::encoding_error, signer::ecdsa::BinaryEcdsaSignature,
    signer::ed25519::BinaryEd25519Signature,
};
use async_trait::async_trait;
use binary_stream::futures::{
    BinaryReader, BinaryWriter, Decodable, Encodable,
};
use futures::io::{AsyncRead, AsyncSeek, AsyncWrite};
use std::io::Result;

#[async_trait]
impl Encodable for BinaryEcdsaSignature {
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

#[async_trait]
impl Decodable for BinaryEcdsaSignature {
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
