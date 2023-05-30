use crate::{
    crypto::{AeadPack, Algorithm, Nonce, AES_GCM_256, X_CHACHA20_POLY1305},
    Error,
};

use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite,
    AsyncWriteExt,
};

use async_trait::async_trait;
use binary_stream::{
    tokio::{BinaryReader, BinaryWriter, Decode, Encode},
    BinaryError, BinaryResult,
};

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for AeadPack {
    async fn encode<W: AsyncWriteExt + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        match &self.nonce {
            Nonce::Nonce12(ref bytes) => {
                writer.write_u8(12).await?;
                writer.write_bytes(bytes).await?;
            }
            Nonce::Nonce24(ref bytes) => {
                writer.write_u8(24).await?;
                writer.write_bytes(bytes).await?;
            }
        }
        writer.write_u32(self.ciphertext.len() as u32).await?;
        writer.write_bytes(&self.ciphertext).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for AeadPack {
    async fn decode<R: AsyncReadExt + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let nonce_size = reader.read_u8().await?;
        let nonce_buffer = reader.read_bytes(nonce_size as usize).await?;
        match nonce_size {
            12 => {
                self.nonce =
                    Nonce::Nonce12(nonce_buffer.as_slice().try_into()?)
            }
            24 => {
                self.nonce =
                    Nonce::Nonce24(nonce_buffer.as_slice().try_into()?)
            }
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownNonceSize(nonce_size),
                )));
            }
        }
        let len = reader.read_u32().await?;
        self.ciphertext = reader.read_bytes(len as usize).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Encode for Algorithm {
    async fn encode<W: AsyncWriteExt + AsyncSeek + Unpin + Send>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
        writer.write_u8(*self.as_ref()).await?;
        Ok(())
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Decode for Algorithm {
    async fn decode<R: AsyncReadExt + AsyncSeek + Unpin + Send>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
        let id = reader.read_u8().await?;
        *self = match id {
            X_CHACHA20_POLY1305 => Algorithm::XChaCha20Poly1305(id),
            AES_GCM_256 => Algorithm::AesGcm256(id),
            _ => {
                return Err(BinaryError::Boxed(Box::from(
                    Error::UnknownAlgorithm(id),
                )));
            }
        };
        Ok(())
    }
}
